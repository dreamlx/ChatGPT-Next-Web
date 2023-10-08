import { NextRequest } from "next/server";
import { getServerSideConfig } from "../config/server";
import md5 from "spark-md5";
import { ACCESS_CODE_PREFIX } from "../constant";

import { serverHooks } from "next/dist/server/app-render/entry-base";

function getIP(req: NextRequest) {
  let ip = req.ip ?? req.headers.get("x-real-ip");
  const forwardedFor = req.headers.get("x-forwarded-for");

  if (!ip && forwardedFor) {
    ip = forwardedFor.split(",").at(0) ?? "";
  }

  return ip;
}

function parseApiKey(bearToken: string) {
  const token = bearToken.trim().replaceAll("Bearer ", "").trim();
  const isOpenAiKey = !token.startsWith(ACCESS_CODE_PREFIX);

  return {
    accessCode: isOpenAiKey ? "" : token.slice(ACCESS_CODE_PREFIX.length),
    apiKey: isOpenAiKey ? token : "",
  };
}

export async function auth(req: NextRequest) {
  const authToken = req.headers.get("Authorization") ?? "";

  // check if it is openai api key or user token
  const { accessCode, apiKey: token } = parseApiKey(authToken);

  const hashedCode = md5.hash(accessCode ?? "").trim();

  const serverConfig = getServerSideConfig();
  console.log("[Auth] allowed hashed codes: ", [...serverConfig.codes]);
  console.log("[Auth] got access code:", accessCode);
  console.log("[Auth] hashed access code:", hashedCode);
  console.log("[User IP] ", getIP(req));
  console.log("[Time] ", new Date().toLocaleString());
  console.log("[Auth]======================= ");

  // edit by amos[old]: serverConfig.needCode && !serverConfig.codes.has(hashedCode) && !token
  // remove: !serverConfig.codes.has(hashedCode)
  if (serverConfig.needCode && !token && !accessCode) {
    return {
      error: true,
      msg: !accessCode ? "empty access code" : "wrong access code",
    };
  }

  // if user does not provide an api key, inject system api key
  if (!token) {
    const apiKey = serverConfig.apiKey;
    if (apiKey) {
      console.log("[Auth] use system api key");
      req.headers.set("Authorization", `Bearer ${apiKey}`);
    } else {
      console.log("[Auth] admin did not provide an api key");
    }
  } else {
    console.log("[Auth] use user api key");
  }

  // if access code is not empty, check if it is valid
  if (accessCode) {
    const data = await getAccessCodeValid(accessCode);

    console.log("[Auth]", data);
    // if data is null, return network error
    if (!data) {
      console.log("[Auth] network error");
      return {
        error: true,
        msg: "network error",
      };
    }

    // if data.data.status > 400, return error
    if (data.data.status > 400) {
      console.log("[Auth] error", data.message);
      return {
        error: true,
        msg: data.message,
      };
    } else {
      console.log("[Auth] success");
    }
  } else {
    return {
      error: true,
      msg: "empty access code",
    };
  }

  return {
    error: false,
  };
}

// 函数 根据validFor更新expiresAt
export function updateExpiresAt(validFor: number) {
  // validFor 单位为day
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + validFor);
  return expiresAt;
}

export async function getAccessCodeValid(accessCode: string) {
  try {
    const username = "ck_19465cb4cb67a9649058b60d7e78168059bcd818";
    const password = "cs_f20060b646e2ce1dc395d60290bb2a874cd6993b";
    const authCode = Buffer.from(`${username}:${password}`).toString("base64");
    const headers = {
      Authorization: `Basic ${authCode}`,
    };
    const url = `https://ai4all.me/wp-json/lmfwc/v2/licenses`;
    const activate_url = `${url}/activate/${accessCode}`;
    const update_url = `${url}/${accessCode}`;
    const res = await fetch(activate_url, { headers });
    const data = await res.json();

    if (data.data.status < 400) {
      if (
        data.data.validFor &&
        data.data.validFor > 0 &&
        !data.data.expiresAt
      ) {
        const _expiresAt = updateExpiresAt(data.data.validFor);
        const year = _expiresAt.getFullYear();
        const month = String(_expiresAt.getMonth() + 1).padStart(2, "0");
        const day = String(_expiresAt.getDate()).padStart(2, "0");
        const formatted_date = `${year}-${month}-${day}`;
        const mydata = { expires_at: formatted_date };
        console.log("########", mydata);

        const res = await fetch(update_url, {
          method: "PUT",
          headers,
          body: JSON.stringify(mydata),
        }).catch((err) => {
          throw new Error(`网络错误 | Network error: ${err.message}`);
        });
        const data2 = await res.json();
      }
    }

    return data; // 返回实际的验证结果
  } catch (error) {
    // 处理错误情况
    console.error("Error:", error);
    return null;
  }
}
