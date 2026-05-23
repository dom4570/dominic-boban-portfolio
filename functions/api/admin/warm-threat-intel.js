import { handleVirusTotalPrewarmRequest } from "../../../server/virustotal-ip-detail.js";
import {
  rejectUnauthorizedScheduledRequest,
  scheduledRefreshAuthorized,
} from "../../../server/scheduled-refresh-auth.js";

export async function onRequest(context) {
  if (!scheduledRefreshAuthorized(context.request, context.env)) {
    return rejectUnauthorizedScheduledRequest(context.env);
  }

  return handleVirusTotalPrewarmRequest(context.request, context.env);
}
