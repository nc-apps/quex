async function createPasskey() {
  const response = await fetch("/challenge");

  const options = await response.json();

  // const options = PublicKeyCredential.parseCreationOptionsFromJSON(json);
  console.debug("options", options);

  // From base64 to Uint8Array
  options.challenge = Uint8Array.from(atob(options.challenge), (character) =>
    character.charCodeAt(0),
  );

  options.user.id = Uint8Array.from(atob(options.user.id), (character) =>
    character.charCodeAt(0),
  );

  const credential = await navigator.credentials.create({
    publicKey: {
      ...options,
      authenticatorSelection: {
        // tells the authenticator to create a passkey
        residentKey: "required",
        // tells the client / authenticator to request user verification where possible
        // e.g. biometric or device PIN
        userVerification: "preferred",
      },
      extensions: {
        // returns back details about the passkey
        credProps: true,
      },
    },
  });

  console.debug("credential", credential);
}

const form = document.querySelector("form");
form.addEventListener("submit", (event) => {
  event.preventDefault();
  createPasskey();
});

form.querySelector("button").disabled = false;
