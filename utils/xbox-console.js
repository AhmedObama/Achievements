const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");

const {
  ensureXboxDirectSession,
  fetchXboxTitleHistory,
  fetchXboxLocalizedTitleAchievements,
  fetchXboxTitleAchievements,
  normalizeXboxAchievement,
  buildXboxAchievementLocalizationIndex,
  buildXboxAchievementRarityMap,
  resolveXboxTitleArtwork,
  getXboxPcStatus,
  getXboxPcSnapshotDelta,
  isXboxPcTitleBlacklisted,
  normalizeTitleId,
  normalizeXuid,
  normalizeXboxSchemaLanguages,
  writeXboxPcSchema,
  downloadImage,
  reserveConfigPath,
  normalizeDeviceNames,
  indexExistingXboxConfigs,
} = require("./xbox-pc");

const { createLogger } = require("./logger");
const { writeJsonAtomicSync } = require("./atomic-json-store");

const XBOX_CONSOLE_PLATFORM = "xbox-console";

const xboxConsoleLogger = createLogger("xbox-console", {
  level: process.env.XBOX_CONSOLE_LOG_LEVEL || "info",
});

function firstNonEmpty(...values) {
  for (const value of values) {
    const text = String(value || "").trim();
    if (text) return text;
  }
  return "";
}

function sanitizeSegment(value, fallback = "xbox-console") {
  const result = String(value || "")
    .trim()
    .replace(/[<>:"/\\|?*\u0000-\u001f]+/g, "_")
    .replace(/\s+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 160);
  return result || fallback;
}

function sanitizeConfigName(value) {
  const result = String(value || "")
    .trim()
    .replace(/[<>:"/\\|?*\u0000-\u001f]+/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 160);
  return result || "Xbox Console Game";
}

function readXboxCoverSources(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return {};
  }
}

function isXboxConsoleTitle(title, filter = "all") {
  const devices = normalizeDeviceNames(title);

  const is360 = devices.some((d) =>
    /(?:^|[^a-z])(xbox360|xbox_360)(?:$|[^a-z])/.test(d),
  );
  const isOne = devices.some((d) =>
    /(?:^|[^a-z])(xboxone|xbox_one|durango)(?:$|[^a-z])/.test(d),
  );
  const isSeries = devices.some((d) =>
    /(?:^|[^a-z])(xboxseries|xboxseriesx|xboxseriess|scarlett)(?:$|[^a-z])/.test(d),
  );
  const isGeneralXbox = devices.some((d) =>
    /(?:^|[^a-z])(xbox)(?:$|[^a-z])/.test(d),
  );
  const hasConsoleDevice = is360 || isOne || isSeries || isGeneralXbox;

  const hasPcDevice = devices.some((d) =>
    /(?:^|[^a-z])(pc|windows|windowsonecore|win32)(?:$|[^a-z])/.test(d),
  );

  if (!hasConsoleDevice) {
    return false;
  }

  const safeFilter = String(filter || "all").toLowerCase();
  if (safeFilter === "xbox360") {
    return is360;
  }
  if (safeFilter === "modern") {
    // Xbox One & Xbox Series X|S
    return isOne || isSeries || (hasConsoleDevice && !is360);
  }

  return true;
}

function detectConsoleGenerationLabel(title = {}) {
  const devices = normalizeDeviceNames(title);
  const is360 = devices.some((d) =>
    /(?:^|[^a-z])(xbox360|xbox_360|xenon)(?:$|[^a-z])/.test(d),
  );
  if (is360) {
    return "Xbox 360";
  }
  const isOne = devices.some((d) =>
    /(?:^|[^a-z])(xboxone|xbox_one|durango)(?:$|[^a-z])/.test(d),
  );
  if (isOne) {
    return "Xbox One";
  }
  const isSeries = devices.some((d) =>
    /(?:^|[^a-z])(xboxseries|xboxseriesx|xboxseriess|scarlett)(?:$|[^a-z])/.test(d),
  );
  if (isSeries) {
    return "Xbox Series X|S";
  }
  return "Xbox Console";
}

function reserveConsoleConfigPath(
  configsDir,
  title,
  existingPath = "",
  generationLabel = "Xbox Console",
) {
  if (existingPath) return existingPath;
  const base = sanitizeConfigName(`${title} (${generationLabel})`);
  let candidate = path.join(configsDir, `${base}.json`);
  let suffix = 2;
  while (fs.existsSync(candidate)) {
    candidate = path.join(configsDir, `${base} ${suffix}.json`);
    suffix += 1;
  }
  return candidate;
}

/**
 * Import all Xbox titles from the authenticated account's history that were
 * playable or played on console (Xbox 360, Xbox One, Xbox Series X|S),
 * with optional generation filtering and automatic deduplication against
 * games already imported into Xbox PC.
 *
 * Auth is shared with the existing xbox-pc integration — no second login needed.
 */
async function importXboxConsoleLibrary(configsDir, options = {}) {
  const userDataDir = String(options.userDataDir || "").trim();
  const schemaRoot = path.join(
    options.schemaRootDir || path.join(configsDir, "schema"),
    XBOX_CONSOLE_PLATFORM,
  );
  const stateRoot = path.join(
    options.stateRootDir || path.join(userDataDir, "xbox-console"),
    "titles",
  );
  const auth = await ensureXboxDirectSession({ ...options, userDataDir });
  const account = {
    xuid: auth.xuid,
    gamertag: auth.gamertag,
  };

  const history = await fetchXboxTitleHistory({ ...options, auth });

  const titleMap = new Map();
  for (const title of history) {
    const titleId = normalizeTitleId(title?.titleId ?? title?.id);
    if (titleId) titleMap.set(titleId, title);
  }

  const titles = [...titleMap.values()];
  const existing = indexExistingXboxConfigs(configsDir, XBOX_CONSOLE_PLATFORM);
  const existingPc = indexExistingXboxConfigs(configsDir, "xbox-pc");

  const result = {
    provider: "Microsoft / Xbox Network (Console)",
    account,
    historyTotal: history.length,
    consoleTitles: titles.length,
    created: 0,
    updated: 0,
    skipped: 0,
    duplicateSkipped: 0,
    blacklistedSkipped: 0,
    failed: 0,
    imported: [],
  };

  await fsp.mkdir(configsDir, { recursive: true });

  let index = 0;
  for (const title of titles) {
    index += 1;
    const titleId = normalizeTitleId(title?.titleId ?? title?.id);
    const titleName = firstNonEmpty(
      title?.name,
      title?.titleName,
      title?.displayName,
      `Xbox ${titleId}`,
    );

    options.onProgress?.({
      current: index,
      total: titles.length,
      percent: Math.round((index / Math.max(1, titles.length)) * 100),
      detail: titleName,
      appid: titleId,
    });

    if (!titleId) {
      result.skipped += 1;
      continue;
    }

    // Platform & generation filter
    if (!isXboxConsoleTitle(title, options.filter || "all")) {
      result.skipped += 1;
      continue;
    }

    // Deduplication against Xbox PC imports
    if (options.skipPcDuplicates !== false && existingPc.has(titleId)) {
      result.skipped += 1;
      result.duplicateSkipped += 1;
      xboxConsoleLogger.info("xbox-console:import-title-skipped-pc-duplicate", {
        titleId,
        title: titleName,
      });
      continue;
    }

    if (isXboxPcTitleBlacklisted(titleId, { ...options, platform: XBOX_CONSOLE_PLATFORM })) {
      result.skipped += 1;
      result.blacklistedSkipped += 1;
      xboxConsoleLogger.info("xbox-console:import-title-skipped-blacklisted", {
        titleId,
        title: titleName,
      });
      continue;
    }

    try {
      const localized = await fetchXboxLocalizedTitleAchievements(
        account.xuid,
        titleId,
        options.schemaLanguages,
        { ...options, auth },
      );

      const achievementRows = localized.achievements;
      if (!achievementRows.length) {
        result.skipped += 1;
        continue;
      }

      const schemaDir = path.join(schemaRoot, sanitizeSegment(titleId));
      const stateDir = path.join(stateRoot, sanitizeSegment(titleId));
      const { schema, snapshot } = await writeXboxPcSchema(
        schemaDir,
        titleId,
        achievementRows,
        {
          ...options,
          schemaLanguages: localized.languages,
          localizedAchievements: localized.localizedAchievements,
        },
      );

      // Download cover art
      const artwork = resolveXboxTitleArtwork(title);
      if ((artwork.coverUrl || artwork.headerUrl) && userDataDir) {
        const coverDir = path.join(
          userDataDir,
          "images",
          XBOX_CONSOLE_PLATFORM,
          titleId,
        );
        const coverPath = path.join(coverDir, `${titleId}.jpg`);
        const headerPath = path.join(coverDir, "header.jpg");
        const sourcesPath = path.join(coverDir, "sources.json");
        const previousSources = readXboxCoverSources(sourcesPath);
        const savedSources = {};
        try {
          if (artwork.coverUrl) {
            const savedCover = await downloadImage(
              artwork.coverUrl,
              coverPath,
              options.timeoutMs,
              {
                overwrite: previousSources.coverUrl !== artwork.coverUrl,
                imageOptions: { width: 300, height: 450, format: "jpg" },
              },
            );
            if (savedCover) savedSources.coverUrl = artwork.coverUrl;
          }
          if (
            artwork.headerUrl &&
            artwork.headerUrl === artwork.coverUrl &&
            savedSources.coverUrl
          ) {
            await fsp.copyFile(coverPath, headerPath);
            savedSources.headerUrl = artwork.headerUrl;
          } else if (artwork.headerUrl) {
            const savedHeader = await downloadImage(
              artwork.headerUrl,
              headerPath,
              options.timeoutMs,
              {
                overwrite: previousSources.headerUrl !== artwork.headerUrl,
                imageOptions: { width: 640, height: 360, format: "jpg" },
              },
            );
            if (savedHeader) savedSources.headerUrl = artwork.headerUrl;
          }
          if (savedSources.coverUrl || savedSources.headerUrl) {
            await fsp.mkdir(coverDir, { recursive: true });
            await fsp.writeFile(
              sourcesPath,
              JSON.stringify(savedSources, null, 2),
              "utf8",
            );
          }
        } catch {}
      }

      writeJsonAtomicSync(path.join(stateDir, "achievements.json"), snapshot);

      const previousEntry = existing.get(titleId);
      const previous = previousEntry?.config || {};
      const generationLabel = detectConsoleGenerationLabel(title);
      const displayName = `${titleName} (${generationLabel})`;

      let filePath = previousEntry?.filePath || "";
      let oldPathToClean = "";
      if (
        !filePath ||
        path.basename(filePath, ".json").includes("(Xbox Console)")
      ) {
        if (filePath && path.basename(filePath, ".json").includes("(Xbox Console)")) {
          oldPathToClean = filePath;
        }
        filePath = reserveConsoleConfigPath(
          configsDir,
          titleName,
          "",
          generationLabel,
        );
      }

      const config = {
        ...previous,
        name: path.basename(filePath, ".json"),
        displayName: displayName,
        appid: titleId,
        platform: XBOX_CONSOLE_PLATFORM,
        xbox_title_id: titleId,
        xbox_xuid: account.xuid,
        xbox_gamertag: account.gamertag,
        xbox_generation: generationLabel,
        xbox_devices: normalizeDeviceNames(title),
        config_path: schemaDir,
        save_path: stateDir,
        executable: previous.executable || "",
        arguments: previous.arguments || "",
        process_name: previous.process_name || "",
        achievement_source: {
          provider: XBOX_CONSOLE_PLATFORM,
          title_id: titleId,
          xuid: account.xuid,
          gamertag: account.gamertag,
          generation: generationLabel,
          snapshot_file: path.join(stateDir, "achievements.json"),
          poll_interval_ms: Math.max(
            10000,
            Number(options.pollIntervalMs) || 30000,
          ),
        },
      };

      await fsp.writeFile(filePath, JSON.stringify(config, null, 2), "utf8");

      if (
        oldPathToClean &&
        oldPathToClean !== filePath &&
        fs.existsSync(oldPathToClean)
      ) {
        try {
          fs.unlinkSync(oldPathToClean);
          xboxConsoleLogger.info("xbox-console:migrated-legacy-config-name", {
            titleId,
            from: oldPathToClean,
            to: filePath,
          });
        } catch (cleanupErr) {
          xboxConsoleLogger.warn("xbox-console:legacy-config-cleanup-failed", {
            error: cleanupErr?.message || String(cleanupErr),
          });
        }
      }

      if (previousEntry) result.updated += 1;
      else result.created += 1;

      result.imported.push({
        name: config.name,
        title: titleName,
        appid: titleId,
        snapshot,
        achievementsCount: schema.length,
      });
    } catch (error) {
      result.failed += 1;
      xboxConsoleLogger.warn("xbox-console:import-title-failed", {
        titleId,
        title: titleName,
        error: error?.message || String(error),
      });
    }
  }

  xboxConsoleLogger.info("xbox-console:import-library-complete", {
    xuid: account.xuid,
    historyTotal: result.historyTotal,
    consoleTitles: result.consoleTitles,
    created: result.created,
    updated: result.updated,
    skipped: result.skipped,
    blacklistedSkipped: result.blacklistedSkipped,
    failed: result.failed,
  });

  return result;
}

async function syncXboxConsoleAchievements(config = {}, options = {}) {
  const xuid = normalizeXuid(options.xuid || config.xbox_xuid);
  const titleId = normalizeTitleId(
    options.titleId || config.xbox_title_id || config.appid,
  );
  const achievements = await fetchXboxTitleAchievements(xuid, titleId, {
    ...options,
    unlockedOnly: false,
  });
  const snapshot = {};
  for (const raw of achievements) {
    const achievement = normalizeXboxAchievement(raw);
    if (achievement) snapshot[achievement.id] = achievement.snapshot;
  }
  return { xuid, titleId, snapshot, total: achievements.length };
}

/**
 * Re-export getXboxPcStatus so callers only need to import from this module.
 * Console and PC share the same auth file, so status is identical.
 */
async function getXboxConsoleStatus(options = {}) {
  return getXboxPcStatus(options);
}

module.exports = {
  XBOX_CONSOLE_PLATFORM,
  getXboxConsoleStatus,
  importXboxConsoleLibrary,
  syncXboxConsoleAchievements,
  getXboxPcSnapshotDelta,
  isXboxConsoleTitle,
  detectConsoleGenerationLabel,
};
