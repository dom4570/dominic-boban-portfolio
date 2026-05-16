import { handleSpamhausIpDetailRequest } from "../../server/spamhaus-ip-detail.js";

export async function onRequest(context) {
  return handleSpamhausIpDetailRequest(context.request, context.env);
}
