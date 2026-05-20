import { handleVirusTotalIpDetailRequest } from "../../server/virustotal-ip-detail.js";

export async function onRequest(context) {
  return handleVirusTotalIpDetailRequest(context.request, context.env);
}
