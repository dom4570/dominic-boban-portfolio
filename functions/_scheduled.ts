import { handleThreatMapRefreshRequest } from "../server/abuse-origin-map.js";

export default {
  async scheduled(event, env, ctx) {
    const fakeRequest = new Request("https://example.com/api/scheduled/threat-map-refresh", {
      method: "POST",
    });

    const response = await handleThreatMapRefreshRequest(fakeRequest, env, ctx);
    const result = await response.json();

    console.log("Scheduled threat map refresh completed:", result);

    if (result?.status === "unavailable" || result?.status === "not_configured") {
      throw new Error(`Refresh failed with status: ${result.status}`);
    }

    return result;
  },
};
