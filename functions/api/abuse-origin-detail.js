import { handleAbuseOriginDetailRequest } from "../../server/abuse-origin-map.js";

export async function onRequest(context) {
  return handleAbuseOriginDetailRequest(context.request, context.env);
}
