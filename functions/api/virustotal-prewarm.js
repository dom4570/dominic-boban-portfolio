import { handleVirusTotalPrewarmRequest } from "../../server/virustotal-ip-detail.js";

export async function onRequest(context) {
  return handleVirusTotalPrewarmRequest(context.request, context.env);
}
