rootProject.name = "messaging-android"

include(":mtproto")
// The app module is not included here: this repository ships the protocol
// implementation and its tests, which is the part that must stay in step with
// the server. The UI lives in the Android app repository.
