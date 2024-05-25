async function test() {
  if (
    !window.PublicKeyCredential ||
    !window.PublicKeyCredential.isConditionalMediationAvailable
  )
    return;

  const isAvialable =
    await PublicKeyCredential.isConditionalMediationAvailable();

  if (!isAvialable) return;

  //TODO Get server options for navigator.credentials.get()
  const response = await navigator.credentials.get({
    mediation: "conditional",
    publicKey: {
      userVerification: "preferred",
    },
  });
}

test();
