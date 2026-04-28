const jsonHeaders = {
  "Content-Type": "application/json; charset=utf-8",
};

const requiredFieldMissing = (value) => typeof value !== "string" || value.trim().length === 0;

export async function onRequestPost({ request, env }) {
  const accessKey = env.WEB3FORMS_ACCESS_KEY;

  if (!accessKey) {
    return Response.json(
      { success: false, message: "Contact service is not configured." },
      { status: 500, headers: jsonHeaders },
    );
  }

  const incomingForm = await request.formData().catch(() => null);

  if (!incomingForm) {
    return Response.json(
      { success: false, message: "Invalid form submission." },
      { status: 400, headers: jsonHeaders },
    );
  }

  const name = String(incomingForm.get("name") || "").trim();
  const email = String(incomingForm.get("email") || "").trim();
  const message = String(incomingForm.get("message") || "").trim();

  if (requiredFieldMissing(name) || requiredFieldMissing(email) || requiredFieldMissing(message)) {
    return Response.json(
      { success: false, message: "Name, email, and message are required." },
      { status: 400, headers: jsonHeaders },
    );
  }

  const outgoingForm = new FormData();
  outgoingForm.append("access_key", accessKey);
  outgoingForm.append("from_name", "Dominic Boban Portfolio");
  outgoingForm.append("subject", `Portfolio enquiry from ${name}`);
  outgoingForm.append("name", name);
  outgoingForm.append("email", email);
  outgoingForm.append("replyto", email);
  outgoingForm.append("message", message);

  const response = await fetch("https://api.web3forms.com/submit", {
    method: "POST",
    body: outgoingForm,
  });
  const result = await response.json().catch(() => null);

  if (!response.ok || result?.success === false) {
    return Response.json(
      { success: false, message: "Web3Forms submission failed." },
      { status: 502, headers: jsonHeaders },
    );
  }

  return Response.json({ success: true }, { headers: jsonHeaders });
}

export function onRequestGet() {
  return Response.json(
    { success: false, message: "Method not allowed." },
    { status: 405, headers: { ...jsonHeaders, Allow: "POST" } },
  );
}
