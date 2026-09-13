"use strict";

const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const axios = require("axios");
const {
  exchangeNpssoForAccessCode,
  exchangeAccessCodeForAuthTokens,
  exchangeRefreshTokenForAuthTokens,
  getUserTitles,
  getTitleTrophies,
  getUserTrophiesEarnedForTitle,
  getProfileFromAccountId,
} = require("psn-api");

const { createLogger } = require("./logger");
const { writeJsonAtomicSync } = require("./atomic-json-store");
const { sanitizeConfigName } = require("./config-name");

const psnLogger = createLogger("psn", {
  level: process.env.PSN_LOG_LEVEL || "info",
});

const PSN_PLATFORM = "psn";
const PSN_AUTH_FILE = "psn-auth.json";

function sanitizeSegment(value, fallback = "psn") {
  const clean = String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return clean || fallback;
}

function normalizeNpCommunicationId(value) {
  const raw = String(value ?? "").trim();
  return /^[A-Za-z0-9_:-]{3,64}$/.test(raw) ? raw : "";
}

function resolveAuthPath(userDataDir) {
  return path.join(path.resolve(String(userDataDir || ".")), PSN_AUTH_FILE);
}

async function loadPsnAuth(userDataDir) {
  const authPath = resolveAuthPath(userDataDir);
  try {
    const raw = await fsp.readFile(authPath, "utf8");
    return JSON.parse(raw);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      psnLogger.warn("psn:load-auth-failed", {
        path: authPath,
        error: error?.message || String(error),
      });
    }
    return null;
  }
}

async function savePsnAuth(userDataDir, auth = {}) {
  const authPath = resolveAuthPath(userDataDir);
  await fsp.mkdir(path.dirname(authPath), { recursive: true });
  await fsp.writeFile(authPath, JSON.stringify(auth, null, 2), "utf8");
}

async function clearPsnAuth(userDataDir) {
  const authPath = resolveAuthPath(userDataDir);
  try {
    await fsp.unlink(authPath);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      psnLogger.warn("psn:clear-auth-failed", {
        path: authPath,
        error: error?.message || String(error),
      });
    }
  }
}

function decodeJwtPayload(token) {
  if (!token || typeof token !== "string") return null;
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = Buffer.from(base64, "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

async function exchangeNpssoForAuthSession(npsso, options = {}) {
  const cleanNpsso = String(npsso || "").trim();
  if (!cleanNpsso) {
    throw new Error("psn-npsso-required");
  }

  psnLogger.info("psn:exchanging-npsso-for-access-code");
  const accessCode = await exchangeNpssoForAccessCode(cleanNpsso);
  if (!accessCode) {
    throw new Error("psn-access-code-failed");
  }

  psnLogger.info("psn:exchanging-access-code-for-tokens");
  const authTokens = await exchangeAccessCodeForAuthTokens(accessCode);
  if (!authTokens?.accessToken) {
    throw new Error("psn-tokens-failed");
  }

  const now = Date.now();
  const expiresInMs = (Number(authTokens.expiresIn) || 3600) * 1000;
  const expiresAt = now + expiresInMs;

  const idPayload = decodeJwtPayload(authTokens.idToken);
  const accessPayload = decodeJwtPayload(authTokens.accessToken);
  const accountId = String(idPayload?.sub || accessPayload?.account_id || "").trim();
  const tokenOnlineId = String(idPayload?.online_id || idPayload?.preferred_username || "").trim();

  let profile = null;
  if (accountId && accountId !== "me") {
    try {
      profile = await getProfileFromAccountId(
        { accessToken: authTokens.accessToken },
        accountId,
      );
    } catch (profErr) {
      psnLogger.warn("psn:fetch-profile-warning", {
        error: profErr?.message || String(profErr),
      });
    }
  }

  const onlineId =
    profile?.onlineId ||
    profile?.profile?.onlineId ||
    tokenOnlineId ||
    "";

  const avatarUrl =
    profile?.avatars?.[0]?.url ||
    profile?.personalDetail?.profilePictureUrls?.[0]?.profilePictureUrl ||
    "";

  const session = {
    npsso: cleanNpsso,
    accessToken: authTokens.accessToken,
    refreshToken: authTokens.refreshToken,
    expiresIn: authTokens.expiresIn,
    expiresAt,
    idToken: authTokens.idToken || "",
    accountId: accountId || "me",
    onlineId,
    avatarUrl,
    updatedAt: new Date(now).toISOString(),
  };

  const userDataDir = String(options.userDataDir || "").trim();
  if (userDataDir) {
    await savePsnAuth(userDataDir, session);
  }

  psnLogger.info("psn:authentication-success", {
    onlineId: session.onlineId,
    accountId: session.accountId,
  });

  return session;
}

async function ensurePsnSession(options = {}) {
  const userDataDir = String(options.userDataDir || "").trim();
  let auth = await loadPsnAuth(userDataDir);

  if (!auth?.accessToken) {
    throw new Error("psn-auth-required");
  }

  const now = Date.now();
  const bufferMs = 5 * 60 * 1000; // 5 minute buffer
  const isExpiring = !auth.expiresAt || auth.expiresAt <= now + bufferMs;

  // Self-heal onlineId and avatarUrl from idToken / profile if missing
  if ((!auth.onlineId || !auth.avatarUrl || auth.accountId === "me") && auth.accessToken) {
    const idPayload = decodeJwtPayload(auth.idToken);
    const accessPayload = decodeJwtPayload(auth.accessToken);
    const accountId = String(idPayload?.sub || accessPayload?.account_id || auth.accountId || "").trim();
    const tokenOnlineId = String(idPayload?.online_id || idPayload?.preferred_username || "").trim();

    let updated = false;
    if (accountId && accountId !== "me" && auth.accountId !== accountId) {
      auth.accountId = accountId;
      updated = true;
    }
    if (tokenOnlineId && !auth.onlineId) {
      auth.onlineId = tokenOnlineId;
      updated = true;
    }
    if ((!auth.avatarUrl || !auth.onlineId) && auth.accountId && auth.accountId !== "me") {
      try {
        const profile = await getProfileFromAccountId({ accessToken: auth.accessToken }, auth.accountId);
        if (profile?.onlineId && auth.onlineId !== profile.onlineId) {
          auth.onlineId = profile.onlineId;
          updated = true;
        }
        const avatar = profile?.avatars?.[0]?.url || profile?.personalDetail?.profilePictureUrls?.[0]?.profilePictureUrl || "";
        if (avatar && auth.avatarUrl !== avatar) {
          auth.avatarUrl = avatar;
          updated = true;
        }
      } catch {}
    }
    if (updated && userDataDir) {
      await savePsnAuth(userDataDir, auth).catch(() => {});
    }
  }

  if (!isExpiring) {
    return auth;
  }

  psnLogger.info("psn:access-token-refreshing");
  try {
    if (auth.refreshToken) {
      const refreshed = await exchangeRefreshTokenForAuthTokens(
        auth.refreshToken,
      );
      const expiresInMs = (Number(refreshed.expiresIn) || 3600) * 1000;
      auth = {
        ...auth,
        accessToken: refreshed.accessToken,
        refreshToken: refreshed.refreshToken || auth.refreshToken,
        expiresIn: refreshed.expiresIn,
        expiresAt: now + expiresInMs,
        updatedAt: new Date(now).toISOString(),
      };
      await savePsnAuth(userDataDir, auth);
      psnLogger.info("psn:token-refresh-success");
      return auth;
    }
  } catch (refreshErr) {
    psnLogger.warn("psn:refresh-token-failed, attempting NPSSO re-auth", {
      error: refreshErr?.message || String(refreshErr),
    });
  }

  if (auth.npsso) {
    return exchangeNpssoForAuthSession(auth.npsso, options);
  }

  throw new Error("psn-session-expired");
}

async function getPsnStatus(options = {}) {
  try {
    const auth = await ensurePsnSession(options);
    return {
      authenticated: true,
      onlineId: auth.onlineId || "PlayStation User",
      accountId: auth.accountId || "",
      avatarUrl: auth.avatarUrl || "",
    };
  } catch (error) {
    return {
      authenticated: false,
      onlineId: "",
      accountId: "",
      avatarUrl: "",
      error: error?.message || String(error),
    };
  }
}

function detectPsnGenerationLabel(title = {}) {
  const platform = String(
    title?.trophyTitlePlatform || title?.platform || "",
  )
    .trim()
    .toUpperCase();
  if (platform.includes("PS5")) return "PS5";
  if (platform.includes("PS4")) return "PS4";
  if (platform.includes("PS3")) return "PS3";
  if (platform.includes("VITA")) return "PS Vita";
  if (platform.includes("PSP")) return "PSP";
  return "PlayStation";
}

function isPsnTitleMatchingFilter(title = {}, filter = "all") {
  const cleanFilter = String(filter || "all").toLowerCase();
  if (cleanFilter === "all") return true;

  const platform = String(
    title?.trophyTitlePlatform || title?.platform || "",
  )
    .trim()
    .toUpperCase();

  if (cleanFilter === "ps5") {
    return platform.includes("PS5");
  }
  if (cleanFilter === "ps4") {
    return platform.includes("PS4");
  }
  if (cleanFilter === "ps3_vita" || cleanFilter === "ps3") {
    return platform.includes("PS3") || platform.includes("VITA");
  }
  return true;
}

function reservePsnConfigPath(
  configsDir,
  title,
  existingPath = "",
  generationLabel = "PlayStation",
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

function parseUnlockTime(value) {
  if (!value) return 0;
  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

async function downloadImage(url, outputPath, timeoutMs = 15000, options = {}) {
  if (!/^https?:\/\//i.test(String(url || ""))) return "";
  try {
    if (
      options.overwrite !== true &&
      fs.existsSync(outputPath) &&
      fs.statSync(outputPath).size > 0
    ) {
      return outputPath;
    }
  } catch {}
  try {
    const response = await axios.get(url, {
      timeout: Math.max(3000, Number(timeoutMs) || 15000),
      responseType: "arraybuffer",
      validateStatus: (status) => status >= 200 && status < 500,
    });
    if (response.status >= 400 || !response.data) return "";
    await fsp.mkdir(path.dirname(outputPath), { recursive: true });
    await fsp.writeFile(outputPath, Buffer.from(response.data));
    return outputPath;
  } catch {
    return "";
  }
}

async function fetchPsnUserTitles(authorization, options = {}) {
  const allTitles = [];
  let offset = 0;
  const limit = 100;

  while (true) {
    psnLogger.info("psn:fetch-titles-page", { offset, limit });
    const res = await getUserTitles(authorization, "me", {
      limit,
      offset,
      ...options,
    });

    const titles = Array.isArray(res?.trophyTitles) ? res.trophyTitles : [];
    if (!titles.length) break;

    allTitles.push(...titles);

    const totalCount = Number(res?.totalItemCount) || 0;
    offset += titles.length;

    if (offset >= totalCount || titles.length < limit) {
      break;
    }
  }

  return allTitles;
}

async function fetchPsnTitleTrophies(authorization, npCommunicationId) {
  try {
    const res = await getTitleTrophies(
      authorization,
      npCommunicationId,
      "all",
    );
    if (Array.isArray(res?.trophies) && res.trophies.length > 0) {
      return res.trophies;
    }
  } catch (err) {
    psnLogger.info("psn:get-trophies-all-failed-trying-default", {
      npCommunicationId,
      error: err?.message || String(err),
    });
  }

  try {
    const resDefault = await getTitleTrophies(
      authorization,
      npCommunicationId,
      "default",
    );
    if (Array.isArray(resDefault?.trophies)) {
      return resDefault.trophies;
    }
  } catch (err) {
    psnLogger.warn("psn:get-trophies-default-failed", {
      npCommunicationId,
      error: err?.message || String(err),
    });
  }

  return [];
}

async function fetchPsnUserEarnedTrophies(authorization, npCommunicationId) {
  try {
    const res = await getUserTrophiesEarnedForTitle(
      authorization,
      "me",
      npCommunicationId,
      "all",
    );
    if (Array.isArray(res?.trophies)) {
      return res.trophies;
    }
  } catch (err) {
    psnLogger.info("psn:get-user-trophies-all-failed-trying-default", {
      npCommunicationId,
      error: err?.message || String(err),
    });
  }

  try {
    const resDefault = await getUserTrophiesEarnedForTitle(
      authorization,
      "me",
      npCommunicationId,
      "default",
    );
    if (Array.isArray(resDefault?.trophies)) {
      return resDefault.trophies;
    }
  } catch (err) {
    psnLogger.warn("psn:get-user-trophies-default-failed", {
      npCommunicationId,
      error: err?.message || String(err),
    });
  }

  return [];
}

function indexExistingPsnConfigs(configsDir) {
  const byId = new Map();
  let files = [];
  try {
    files = fs
      .readdirSync(configsDir)
      .filter((f) => f.toLowerCase().endsWith(".json"));
  } catch {
    return byId;
  }

  for (const file of files) {
    try {
      const filePath = path.join(configsDir, file);
      const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
      if (String(data?.platform || "").toLowerCase() !== PSN_PLATFORM) continue;
      const commId = normalizeNpCommunicationId(
        data?.psn_communication_id || data?.appid,
      );
      if (commId) {
        byId.set(commId, { filePath, config: data });
      }
    } catch {}
  }
  return byId;
}

async function importPsnLibrary(configsDir, options = {}) {
  const userDataDir = String(options.userDataDir || "").trim();
  const schemaRoot = path.join(
    options.schemaRootDir || path.join(configsDir, "schema"),
    PSN_PLATFORM,
  );
  const stateRoot = path.join(
    options.stateRootDir || path.join(userDataDir, PSN_PLATFORM),
    "titles",
  );

  const auth = await ensurePsnSession({ ...options, userDataDir });
  const authorization = { accessToken: auth.accessToken };

  psnLogger.info("psn:import-fetching-titles", { onlineId: auth.onlineId });
  const titles = await fetchPsnUserTitles(authorization, options);

  const existing = indexExistingPsnConfigs(configsDir);

  const result = {
    provider: "Sony PlayStation Network",
    account: {
      onlineId: auth.onlineId,
      accountId: auth.accountId,
    },
    totalTitles: titles.length,
    created: 0,
    updated: 0,
    skipped: 0,
    failed: 0,
    imported: [],
  };

  await fsp.mkdir(configsDir, { recursive: true });

  let index = 0;
  for (const title of titles) {
    index += 1;
    const npCommunicationId = normalizeNpCommunicationId(
      title?.npCommunicationId,
    );
    const titleName = String(title?.trophyTitleName || "").trim();

    if (!npCommunicationId || !titleName) {
      result.skipped += 1;
      continue;
    }

    if (
      options.filter &&
      !isPsnTitleMatchingFilter(title, options.filter)
    ) {
      result.skipped += 1;
      continue;
    }

    if (typeof options.onProgress === "function") {
      try {
        options.onProgress({
          index,
          total: titles.length,
          title: titleName,
          npCommunicationId,
        });
      } catch {}
    }

    try {
      const trophies = await fetchPsnTitleTrophies(
        authorization,
        npCommunicationId,
      );
      if (!trophies.length) {
        result.skipped += 1;
        continue;
      }

      const earnedList = await fetchPsnUserEarnedTrophies(
        authorization,
        npCommunicationId,
      );
      const earnedMap = new Map();
      for (const e of earnedList) {
        if (e.trophyId !== undefined) {
          earnedMap.set(e.trophyId, e);
        }
      }

      const schemaDir = path.join(schemaRoot, sanitizeSegment(npCommunicationId));
      const stateDir = path.join(stateRoot, sanitizeSegment(npCommunicationId));
      const imgDir = path.join(schemaDir, "img");
      await fsp.mkdir(imgDir, { recursive: true });
      await fsp.mkdir(stateDir, { recursive: true });

      const schema = [];
      const snapshot = {};

      for (const t of trophies) {
        const idStr = String(t.trophyId);
        const iconFilename = `${idStr}.png`;
        const iconPath = path.join(imgDir, iconFilename);

        if (t.trophyIconUrl) {
          try {
            await downloadImage(t.trophyIconUrl, iconPath, 10000);
          } catch {}
        }

        const trophyType = String(t.trophyType || "bronze").toLowerCase();
        schema.push({
          name: idStr,
          displayName: { english: t.trophyName || idStr },
          description: { english: t.trophyDetail || "" },
          icon: path.join("img", iconFilename),
          icon_gray: path.join("img", iconFilename),
          hidden: t.trophyHidden ? 1 : 0,
          trophyType,
          trophyGroupId: t.trophyGroupId || "default",
        });

        const userEarned = earnedMap.get(t.trophyId);
        snapshot[idStr] = {
          earned: userEarned?.earned === true,
          earned_time: parseUnlockTime(userEarned?.earnedDateTime),
          progress:
            userEarned?.progress !== undefined
              ? Number(userEarned.progress)
              : undefined,
        };
      }

      await fsp.writeFile(
        path.join(schemaDir, "achievements.json"),
        JSON.stringify(schema, null, 2),
        "utf8",
      );

      writeJsonAtomicSync(path.join(stateDir, "achievements.json"), snapshot);

      // Download cover image
      if (title.trophyTitleIconUrl && userDataDir) {
        const coverDir = path.join(
          userDataDir,
          "images",
          PSN_PLATFORM,
          npCommunicationId,
        );
        const coverPath = path.join(coverDir, `${npCommunicationId}.jpg`);
        const headerPath = path.join(coverDir, "header.jpg");
        try {
          await downloadImage(title.trophyTitleIconUrl, coverPath, 15000);
          if (fs.existsSync(coverPath)) {
            await fsp.copyFile(coverPath, headerPath);
          }
        } catch {}
      }

      const generationLabel = detectPsnGenerationLabel(title);
      const displayName = `${titleName} (${generationLabel})`;

      const previousEntry = existing.get(npCommunicationId);
      const previous = previousEntry?.config || {};

      const filePath = reservePsnConfigPath(
        configsDir,
        titleName,
        previousEntry?.filePath || "",
        generationLabel,
      );

      const config = {
        ...previous,
        name: path.basename(filePath, ".json"),
        displayName,
        appid: npCommunicationId,
        platform: PSN_PLATFORM,
        psn_communication_id: npCommunicationId,
        psn_account_id: auth.accountId,
        psn_online_id: auth.onlineId,
        psn_platform: title.trophyTitlePlatform || generationLabel,
        psn_generation: generationLabel,
        config_path: schemaDir,
        save_path: stateDir,
        executable: previous.executable || "",
        arguments: previous.arguments || "",
        process_name: previous.process_name || "",
        achievement_source: {
          provider: PSN_PLATFORM,
          communication_id: npCommunicationId,
          account_id: auth.accountId,
          online_id: auth.onlineId,
          generation: generationLabel,
          snapshot_file: path.join(stateDir, "achievements.json"),
          poll_interval_ms: Math.max(
            10000,
            Number(options.pollIntervalMs) || 30000,
          ),
        },
      };

      await fsp.writeFile(filePath, JSON.stringify(config, null, 2), "utf8");

      if (previousEntry) result.updated += 1;
      else result.created += 1;

      result.imported.push({
        name: config.name,
        title: titleName,
        appid: npCommunicationId,
        platform: generationLabel,
        achievementsCount: schema.length,
      });
    } catch (err) {
      result.failed += 1;
      psnLogger.warn("psn:import-title-failed", {
        npCommunicationId,
        title: titleName,
        error: err?.message || String(err),
      });
    }
  }

  psnLogger.info("psn:import-complete", {
    onlineId: auth.onlineId,
    totalTitles: result.totalTitles,
    created: result.created,
    updated: result.updated,
    skipped: result.skipped,
    failed: result.failed,
  });

  return result;
}

async function syncPsnAchievements(config = {}, options = {}) {
  const userDataDir = String(options.userDataDir || "").trim();
  const npCommunicationId = normalizeNpCommunicationId(
    options.npCommunicationId ||
      config.psn_communication_id ||
      config.appid,
  );

  if (!npCommunicationId) {
    throw new Error("psn-communication-id-required");
  }

  const auth = await ensurePsnSession({ ...options, userDataDir });
  const authorization = { accessToken: auth.accessToken };

  const earnedList = await fetchPsnUserEarnedTrophies(
    authorization,
    npCommunicationId,
  );

  const snapshot = {};
  for (const e of earnedList) {
    if (e.trophyId !== undefined) {
      snapshot[String(e.trophyId)] = {
        earned: e.earned === true,
        earned_time: parseUnlockTime(e.earnedDateTime),
        progress:
          e.progress !== undefined ? Number(e.progress) : undefined,
      };
    }
  }

  return {
    npCommunicationId,
    snapshot,
    total: Object.keys(snapshot).length,
    earnedCount: Object.values(snapshot).filter((s) => s.earned).length,
  };
}

module.exports = {
  PSN_PLATFORM,
  PSN_AUTH_FILE,
  clearPsnAuth,
  detectPsnGenerationLabel,
  ensurePsnSession,
  exchangeNpssoForAuthSession,
  fetchPsnTitleTrophies,
  fetchPsnUserEarnedTrophies,
  fetchPsnUserTitles,
  getPsnStatus,
  importPsnLibrary,
  indexExistingPsnConfigs,
  isPsnTitleMatchingFilter,
  loadPsnAuth,
  normalizeNpCommunicationId,
  reservePsnConfigPath,
  savePsnAuth,
  syncPsnAchievements,
};
