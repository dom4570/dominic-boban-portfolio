import { handleAbuseIpdbIpDetailRequest } from "../../server/abuseipdb-ip-detail.js";

export async function onRequest(context) {
  return handleAbuseIpdbIpDetailRequest(context.request, context.env);
}
