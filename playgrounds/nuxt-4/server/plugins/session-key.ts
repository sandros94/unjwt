// #region docs
// A missing or malformed key stops the server at start-up, not at the first sign-in
export default defineNitroPlugin(() => {
  appSession();
});
// #endregion
