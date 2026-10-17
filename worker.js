const EARTHLINK = "https://ubapi.earthlink.iq";
const ALLOWED_ORIGINS = new Set([
  "https://habgit286.github.io",
  "http://localhost:8080",
  "http://127.0.0.1:8080"
]);

function json(data, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": origin || "https://habgit286.github.io",
      "Access-Control-Allow-Credentials": "true",
      "Vary": "Origin"
    }
  });
}

function cors(request) {
  const origin = request.headers.get("Origin") || "";
  const allowed = ALLOWED_ORIGINS.has(origin);

  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": allowed ? origin : "https://habgit286.github.io",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });
}

function getOrigin(request) {
  const origin = request.headers.get("Origin") || "";
  return ALLOWED_ORIGINS.has(origin) ? origin : "https://habgit286.github.io";
}

function sessionId(request) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)el_session=([a-f0-9]{48,80})/);
  return match ? match[1] : "";
}

function cookieHeader(id, maxAge = 3600) {
  return `el_session=${id}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${maxAge}`;
}

async function earthlinkPost(path, token, body = "") {
  const headers = {
    "Accept": "application/json, text/plain, */*",
    "Origin": "https://user.earthlink.iq",
    "Referer": "https://user.earthlink.iq/"
  };

  if (token) headers.Authorization = `Bearer ${token}`;

  if (typeof body === "string" && body.length) {
    headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8";
  }

  const response = await fetch(EARTHLINK + path, {
    method: "POST",
    headers,
    body: body || undefined,
    redirect: "follow"
  });

  const text = await response.text();
  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text.slice(0, 1200) };
  }

  if (!response.ok) {
    const error = new Error(
      data.error_description ||
      data.message ||
      data.error ||
      `Earthlink HTTP ${response.status}`
    );
    error.status = response.status;
    error.details = data;
    throw error;
  }

  return data;
}

function unwrapValue(field) {
  if (field && typeof field === "object" && "value" in field) {
    return field.value;
  }
  return field ?? null;
}

async function getAccount(token) {
  // CheckSession: المتصفح الأصلي يطلب POST، لذلك لا نستخدم OPTIONS هنا.
  const session = await earthlinkPost("/api/user/CheckSession", token);

  if (
    session &&
    (session.valid === false ||
     session.isValid === false ||
     session.success === false)
  ) {
    throw new Error("جلسة إيرثلنك غير صالحة. سجّل الدخول مرة ثانية.");
  }

  const data = await earthlinkPost("/api/user/GetUserDataAr", token);

  // بعض الاستجابات تكون داخل data أو result.
  const account = data?.result ?? data?.data ?? data?.userData ?? data;

  if (!account || typeof account !== "object") {
    throw new Error("إيرثلنك لم تُرجع بيانات حساب بصيغة JSON متوقعة.");
  }

  return account;
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return cors(request);

    const origin = getOrigin(request);
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (!ALLOWED_ORIGINS.has(request.headers.get("Origin") || "")) {
      return json({ ok: false, error: "مصدر الطلب غير مسموح." }, 403, origin);
    }

    try {
      if (path === "/api/health" && request.method === "GET") {
        return json({
          ok: true,
          service: "Earthlink Secure Gateway",
          earthlink: EARTHLINK,
          time: new Date().toISOString()
        }, 200, origin);
      }

      if (path === "/api/login" && request.method === "POST") {
        const input = await request.json();
        const username = String(input.username || "").trim();
        const password = String(input.password || "");

        if (!username || !password) {
          return json({ ok: false, error: "أدخل اسم المستخدم وكلمة المرور." }, 400, origin);
        }

        const form = new URLSearchParams();
        form.set("grant_type", "password");
        form.set("username", username);
        form.set("password", password);
        form.set("Logintype", "0");

        const tokenResponse = await earthlinkPost(
          "/api/user/Token",
          "",
          form.toString()
        );

        const accessToken = tokenResponse.access_token || tokenResponse.accessToken;
        if (!accessToken) {
          return json({
            ok: false,
            error: tokenResponse.error_description ||
                   tokenResponse.error ||
                   "لم يُرجع خادم إيرثلنك Access Token.",
            diagnostic: {
              fields: Object.keys(tokenResponse || {}),
              error: tokenResponse.error || null
            }
          }, 401, origin);
        }

        // تحقق من الرمز وحاول قراءة البيانات قبل إعلان نجاح الدخول.
        const account = await getAccount(accessToken);

        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        const sid = Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");

        if (!env.SESSIONS) {
          return json({
            ok: false,
            error: "خدمة الجلسات غير مُهيّأة. اربط KV باسم SESSIONS في إعدادات Worker."
          }, 500, origin);
        }

        await env.SESSIONS.put(
          "session:" + sid,
          JSON.stringify({
            accessToken,
            createdAt: Date.now()
          }),
          { expirationTtl: 60 * 60 * 6 }
        );

        return new Response(JSON.stringify({
          ok: true,
          message: "تم تسجيل الدخول.",
          account
        }), {
          status: 200,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Set-Cookie": cookieHeader(sid, 21600),
            "Vary": "Origin"
          }
        });
      }

      if (path === "/api/account" && request.method === "GET") {
        const sid = sessionId(request);
        if (!sid || !env.SESSIONS) {
          return json({ ok: false, error: "انتهت الجلسة؛ سجّل الدخول مجدداً." }, 401, origin);
        }

        const saved = await env.SESSIONS.get("session:" + sid);
        if (!saved) {
          return json({ ok: false, error: "انتهت الجلسة؛ سجّل الدخول مجدداً." }, 401, origin);
        }

        const session = JSON.parse(saved);
        const account = await getAccount(session.accessToken);
        return json({ ok: true, account }, 200, origin);
      }

      if (path === "/api/logout" && request.method === "POST") {
        const sid = sessionId(request);
        if (sid && env.SESSIONS) await env.SESSIONS.delete("session:" + sid);

        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Set-Cookie": cookieHeader("", 0),
            "Cache-Control": "no-store",
            "Vary": "Origin"
          }
        });
      }

      if (path === "/api/reports/discord" && request.method === "POST") {
        if (!env.WEB) {
          return json({ ok: false, error: "لم يُضبط سر WEB في Worker." }, 503, origin);
        }

        const sid = sessionId(request);
        const saved = sid && env.SESSIONS
          ? await env.SESSIONS.get("session:" + sid)
          : null;

        if (!saved) {
          return json({ ok: false, error: "سجّل الدخول أولاً." }, 401, origin);
        }

        const { message } = await request.json();
        const content = String(message || "").trim().slice(0, 1800);
        if (!content) {
          return json({ ok: false, error: "التقرير فارغ." }, 400, origin);
        }

        const sent = await fetch(env.WEB, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content })
        });

        if (!sent.ok) {
          return json({ ok: false, error: `فشل إرسال Discord: HTTP ${sent.status}` }, 502, origin);
        }

        return json({ ok: true, message: "تم إرسال التقرير." }, 200, origin);
      }

      return json({ ok: false, error: "المسار غير موجود." }, 404, origin);
    } catch (error) {
      // لا نرسل رمز الدخول أو كلمة المرور إلى الواجهة.
      return json({
        ok: false,
        error: error.message || "حدث خطأ غير معروف.",
        status: error.status || 500
      }, error.status && error.status >= 400 && error.status < 500 ? error.status : 502, origin);
    }
  }
};
