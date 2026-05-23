import { handleThreatMapRefreshRequest } from "../../../server/abuse-origin-map.js";
import {
  rejectUnauthorizedScheduledRequest,
  scheduledRefreshAuthorized,
} from "../../../server/scheduled-refresh-auth.js";

export async function onRequest(context) {
  if (!scheduledRefreshAuthorized(context.request, context.env)) {
    return rejectUnauthorizedScheduledRequest(context.env);
  }

  return handleThreatMapRefreshRequest(context.request, context.env, context);
}
