async function fetchEarthlinkUserData(token) {
  const response = await fetch(
    "https://ubapi.earthlink.iq/api/user/GetUserDataAr",
    {
      method: "GET",
      headers: {
        "Accept": "*/*",
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": `Bearer ${token}`,
        "Origin": "https://user.earthlink.iq",
        "Referer": "https://user.earthlink.iq/"
      }
    }
  );

  const body = await response.text();

  if (!response.ok) {
    throw new Error(
      `GetUserDataAr failed: HTTP ${response.status} - ${body.slice(0, 500)}`
    );
  }

  try {
    return JSON.parse(body);
  } catch {
    throw new Error("استجابة بيانات إيرثلنك ليست JSON صالحاً");
  }
}
