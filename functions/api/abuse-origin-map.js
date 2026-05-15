import { handleAbuseOriginMapRequest } from "../../server/abuse-origin-map.js";

export async function onRequest(context) {
  return handleAbuseOriginMapRequest(context.request, context.env);
}
