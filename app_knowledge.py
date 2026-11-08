"""
app_knowledge.py - built-in, plain-language notes about common Android packages.

Used by adb_manager.py. Each entry:
    "package.name": (friendly name, risk, what it does, what happens if you turn it off)

risk is one of SAFE / CAUTION / CRITICAL:
    SAFE      - turning it off only loses that app's own features
    CAUTION   - other things may stop working; read the note first
    CRITICAL  - the device may misbehave or fail to start; leave it on

Add your own entries to KNOWN at the bottom (or edit existing ones) - no other
file needs to change.
"""

SAFE, CAUTION, CRITICAL = "safe", "caution", "critical"
# UNKNOWN = not enough evidence to classify. It is NOT "safe": it means the tool
# can't vouch for the app either way. Rendered distinctly from SAFE in the UI.
UNKNOWN = "unknown"

KNOWN = {
    # ------------------------------------------------------------------
    # Core Android - leave these alone
    # ------------------------------------------------------------------
    "android": ("Android system", CRITICAL,
                "The core of Android itself. Every other app runs on top of it.",
                "The device stops working. Never turn this off."),
    "com.android.systemui": ("System UI", CRITICAL,
                             "Draws the status bar, notifications, quick settings, the "
                             "navigation buttons and (on most versions) the lock screen.",
                             "You lose the status bar and navigation buttons; the device "
                             "can become unusable."),
    "com.android.keyguard": ("Lock screen (Keyguard)", CRITICAL,
                             "The lock screen on older Android versions (4.4 era).",
                             "The device may fail to unlock or get stuck after restart."),
    "com.android.settings": ("Settings", CRITICAL,
                             "The Settings app.",
                             "You can no longer change any setting on the device itself."),
    "com.android.providers.settings": ("Settings storage", CRITICAL,
                                       "Stores every system setting (Wi-Fi, sound, display...).",
                                       "Android itself breaks. Never turn this off."),
    "com.android.phone": ("Phone services", CRITICAL,
                          "Runs the mobile network side: calls, SIM card, mobile data.",
                          "No calls or mobile data; on some devices it crashes in a loop."),
    "com.android.server.telecom": ("Call management", CRITICAL,
                                   "Routes and manages phone calls.",
                                   "Calls stop working."),
    "com.android.providers.telephony": ("SMS & mobile data storage", CRITICAL,
                                        "Stores text messages and the mobile data (APN) settings.",
                                        "No SMS and mobile data settings disappear."),
    "com.android.shell": ("Shell", CRITICAL,
                          "Used by ADB (what this program talks through) and by bug reports.",
                          "This program may lose the ability to talk to the device, so you "
                          "could not turn anything back on."),
    "com.android.packageinstaller": ("Package installer", CRITICAL,
                                     "Installs and removes apps. On Android 6-9 it also shows "
                                     "the permission pop-ups.",
                                     "You cannot install apps, and apps cannot ask for permissions."),
    "com.google.android.packageinstaller": ("Package installer (Google)", CRITICAL,
                                            "Google's version of the app installer / permission pop-ups.",
                                            "You cannot install apps, and apps cannot ask for permissions."),
    "com.android.permissioncontroller": ("Permission controller", CRITICAL,
                                         "Shows the permission pop-ups and the permission settings "
                                         "(Android 10 and newer).",
                                         "Apps cannot ask for permissions; parts of Settings break."),
    "com.google.android.permissioncontroller": ("Permission controller (Google)", CRITICAL,
                                                "Google's version of the permission pop-ups (Android 10+).",
                                                "Apps cannot ask for permissions; parts of Settings break."),
    "com.android.ext.services": ("Android Services Library", CRITICAL,
                                 "Small system helpers (notification ranking, storage and "
                                 "autofill helpers).",
                                 "Some versions get stuck while starting. Leave it on."),
    "com.google.android.ext.services": ("Android Services Library (Google)", CRITICAL,
                                        "Google's version of the system helper library.",
                                        "Some versions get stuck while starting. Leave it on."),
    "com.android.providers.media": ("Media storage", CRITICAL,
                                    "Keeps the list of your photos, videos, music and downloads "
                                    "that every app uses.",
                                    "Gallery, camera, music and file apps break."),
    "com.google.android.providers.media.module": ("Media storage (Google)", CRITICAL,
                                                  "Newer, updatable version of media storage (Android 11+).",
                                                  "Gallery, camera, music and file apps break."),

    # ------------------------------------------------------------------
    # Android system parts - be careful
    # ------------------------------------------------------------------
    "com.android.providers.downloads": ("Download manager", CAUTION,
                                        "Downloads files for the Play Store, browsers and other apps.",
                                        "App installs/updates from the Play Store and many downloads fail."),
    "com.android.providers.downloads.ui": ("Downloads", SAFE,
                                           "The app that just lists your downloads.",
                                           "Only the list screen goes away; downloads still work."),
    "com.android.providers.contacts": ("Contacts storage", CAUTION,
                                       "Stores your contacts and call history.",
                                       "Contacts, phone and messaging apps break."),
    "com.android.providers.calendar": ("Calendar storage", CAUTION,
                                       "Stores calendar events for all calendar apps.",
                                       "Calendar apps stop showing events."),
    "com.android.providers.userdictionary": ("User dictionary", SAFE,
                                             "Words you added to the keyboard dictionary.",
                                             "The keyboard forgets your personal words while it is off."),
    "com.android.providers.blockednumber": ("Blocked numbers", CAUTION,
                                            "Stores the numbers you blocked.",
                                            "Blocked callers can get through again."),
    "com.android.providers.partnerbookmarks": ("Partner bookmarks", SAFE,
                                               "Pre-loaded browser bookmarks from the maker or carrier.",
                                               "Nothing noticeable."),
    "com.android.location.fused": ("Fused location", CAUTION,
                                   "Combines GPS, Wi-Fi and mobile towers to work out where you are.",
                                   "Location may stop working in apps."),
    "com.android.defcontainer": ("Package access helper", CAUTION,
                                 "Checks and copies app files during installs (Android 8 and older).",
                                 "Installing apps can fail."),
    "com.android.keychain": ("Key chain", CAUTION,
                             "Stores security certificates used for some Wi-Fi networks, VPNs "
                             "and secure websites.",
                             "Work/school Wi-Fi, VPNs or some secure connections may fail."),
    "com.android.certinstaller": ("Certificate installer", CAUTION,
                                  "Installs security certificates.",
                                  "You cannot add new certificates (needed for some Wi-Fi/VPN)."),
    "com.android.externalstorage": ("External storage", CAUTION,
                                    "Lets file pickers see the internal storage and SD card.",
                                    "Apps cannot open or save files through the file picker."),
    "com.android.documentsui": ("Files / file picker", CAUTION,
                                "The screen apps use to let you pick or save a file.",
                                "Many apps can no longer open or save files."),
    "com.android.mtp": ("USB file transfer (MTP)", SAFE,
                        "Lets a computer see the device's files over USB (Android 7+).",
                        "The computer stops showing the device as a drive. ADB keeps working."),
    "com.android.bluetooth": ("Bluetooth", CAUTION,
                              "The Bluetooth service.",
                              "No Bluetooth at all."),
    "com.android.nfc": ("NFC", CAUTION,
                        "Near-field communication: tap-to-pay, NFC tags, quick pairing.",
                        "No tap-to-pay or NFC features."),
    "com.android.se": ("Secure element", CAUTION,
                       "Secure chip access for payments and some SIM security features.",
                       "Tap-to-pay and some SIM features may fail."),
    "com.android.vpndialogs": ("VPN dialogs", CAUTION,
                               "Shows the 'allow this VPN?' confirmation.",
                               "VPN apps cannot start."),
    "com.android.proxyhandler": ("Proxy handler", CAUTION,
                                 "Applies Wi-Fi proxy settings.",
                                 "Only matters if you use a proxy - it would stop being applied."),
    "com.android.pacprocessor": ("Proxy auto-config", CAUTION,
                                 "Reads automatic proxy scripts for networks that use them.",
                                 "Only matters on networks with automatic proxy setup."),
    "com.android.carrierconfig": ("Carrier settings", CAUTION,
                                  "Settings your mobile operator needs (VoLTE, MMS, etc.).",
                                  "Calls, MMS or mobile data features may misbehave."),
    "com.android.stk": ("SIM toolkit", SAFE,
                        "Menus and messages from your SIM card / operator.",
                        "Operator SIM menus disappear. A few operators use it for services."),
    "com.android.cellbroadcastreceiver": ("Emergency alerts", CAUTION,
                                          "Receives government emergency alerts (earthquake, missing child...).",
                                          "You would not receive emergency alerts."),
    "com.google.android.cellbroadcastreceiver": ("Emergency alerts (Google)", CAUTION,
                                                 "Receives government emergency alerts.",
                                                 "You would not receive emergency alerts."),
    "com.android.webview": ("Android System WebView", CAUTION,
                            "Shows web pages inside other apps (help pages, logins, ads).",
                            "Many apps show blank screens or crash."),
    "com.google.android.webview": ("Android System WebView (Google)", CAUTION,
                                   "Shows web pages inside other apps (help pages, logins, ads).",
                                   "Many apps show blank screens or crash."),
    "com.android.inputmethod.latin": ("Android Keyboard (AOSP)", CAUTION,
                                      "The basic Android keyboard.",
                                      "If it's your only keyboard you can't type anything."),
    "com.android.launcher": ("Launcher (home screen)", CAUTION,
                             "Home screen on older Android.",
                             "If it's your only home screen the Home button does nothing."),
    "com.android.launcher3": ("Launcher3 (home screen)", CAUTION,
                              "The standard Android home screen.",
                              "If it's your only home screen the Home button does nothing."),
    "com.android.inputdevices": ("Input devices", SAFE,
                                 "Keyboard layouts for physical (USB/Bluetooth) keyboards.",
                                 "Only matters if you plug in a hardware keyboard."),
    "com.android.managedprovisioning": ("Work setup", SAFE,
                                        "Sets up work profiles / company-managed devices.",
                                        "Only matters if you use a work profile."),
    "com.android.companiondevicemanager": ("Companion device manager", SAFE,
                                           "Helps pair watches and other companion gadgets.",
                                           "Pairing some watches/bands may fail."),
    "com.android.backupconfirm": ("Backup confirm", SAFE,
                                  "Shows the confirmation screen for 'adb backup'.",
                                  "adb backup / restore won't work."),
    "com.android.sharedstoragebackup": ("Shared storage backup", SAFE,
                                        "Helps back up shared storage files.",
                                        "That part of backups stops."),
    "com.android.localtransport": ("Local backup transport", SAFE,
                                   "Developer backup-to-device option.",
                                   "Nothing noticeable."),
    "com.android.wallpaperbackup": ("Wallpaper backup", SAFE,
                                    "Backs up your wallpaper.",
                                    "Your wallpaper isn't backed up."),
    "com.android.wallpapercropper": ("Wallpaper cropper", SAFE,
                                     "Crop screen used when you set a wallpaper.",
                                     "Setting a wallpaper may not offer cropping."),
    "com.android.wallpaper.livepicker": ("Live wallpaper picker", SAFE,
                                         "Lets you choose animated wallpapers.",
                                         "You can't pick live wallpapers."),
    "com.android.printspooler": ("Print spooler", SAFE,
                                 "Handles printing.",
                                 "You can't print from the device."),
    "com.android.bips": ("Default print service", SAFE,
                         "Built-in printing to common Wi-Fi printers.",
                         "You can't print with the built-in service."),
    "com.android.bookmarkprovider": ("Bookmark provider", SAFE,
                                     "Old bookmark storage, mostly unused.",
                                     "Nothing noticeable."),
    "com.android.captiveportallogin": ("Wi-Fi sign-in", SAFE,
                                       "Opens the login page of hotel/airport Wi-Fi.",
                                       "Wi-Fi networks with a login page won't show it."),
    "com.android.htmlviewer": ("HTML viewer", SAFE,
                               "Shows legal notices / simple web files.",
                               "Legal info screens may not open."),
    "com.android.statementservice": ("Intent filter verification", SAFE,
                                     "Checks which app opens which website links.",
                                     "Links may open in the browser instead of the matching app."),
    "com.android.smspush": ("WAP push", SAFE,
                            "Handles old-style operator push messages.",
                            "Nothing noticeable for most people."),
    "com.android.simappdialog": ("SIM app dialog", SAFE,
                                 "Prompts to install an operator app when a new SIM is inserted.",
                                 "No prompt."),
    "com.android.traceur": ("System tracing", SAFE,
                            "Developer tool for recording performance traces.",
                            "Nothing noticeable."),
    "com.android.dynsystem": ("Dynamic system updates", SAFE,
                              "Developer tool to try other Android images.",
                              "Nothing noticeable."),
    "com.android.emergency": ("Emergency information", SAFE,
                              "Medical info / emergency contacts shown on the lock screen.",
                              "Those details aren't shown."),
    "com.android.storagemanager": ("Storage manager", SAFE,
                                   "Helps free up space automatically.",
                                   "The automatic clean-up feature goes away."),
    "com.android.musicfx": ("Audio effects (MusicFX)", SAFE,
                            "Sound equalizer for music apps.",
                            "No equalizer."),
    "com.android.dreams.basic": ("Basic screensaver", SAFE,
                                 "Simple screensaver shown while charging.",
                                 "That screensaver goes away."),
    "com.android.dreams.phototable": ("Photo screensaver", SAFE,
                                      "Photo table / frame screensaver.",
                                      "That screensaver goes away."),
    "com.android.egg": ("Android Easter egg", SAFE,
                        "The hidden game when you tap the Android version in Settings.",
                        "Nothing noticeable."),
    "com.android.apps.tag": ("NFC tags", SAFE,
                             "Reads NFC tags.",
                             "Tapping NFC tags does nothing."),
    "com.android.facelock": ("Face unlock (old)", SAFE,
                             "Face unlock on Android 4.x.",
                             "Face unlock stops working."),
    "com.android.musicvis": ("Music visualizer wallpapers", SAFE,
                             "Live wallpapers that react to music (Android 4.x).", "Nothing else."),
    "com.android.noisefield": ("Noise Field wallpaper", SAFE, "Live wallpaper (Android 4.x).", "Nothing else."),
    "com.android.phasebeam": ("Phase Beam wallpaper", SAFE, "Live wallpaper (Android 4.x).", "Nothing else."),
    "com.android.magicsmoke": ("Magic Smoke wallpaper", SAFE, "Live wallpaper (Android 4.x).", "Nothing else."),
    "com.android.galaxy4": ("Black Hole wallpaper", SAFE, "Live wallpaper (Android 4.x).", "Nothing else."),

    # AOSP user apps
    "com.android.calendar": ("Calendar (AOSP)", SAFE, "Basic calendar app.", "Only this app goes away; events stay."),
    "com.android.email": ("Email (AOSP)", SAFE, "Basic email app.", "Only this app goes away."),
    "com.android.exchange": ("Exchange services", SAFE, "Work (Exchange) mail sync for the Email app.",
                             "Exchange accounts stop syncing in the Email app."),
    "com.android.browser": ("Browser (AOSP)", SAFE, "The old built-in browser.", "Only this app goes away."),
    "com.android.gallery3d": ("Gallery", SAFE, "Photo gallery.", "Only this app goes away; photos stay."),
    "com.android.music": ("Music (AOSP)", SAFE, "Basic music player.", "Only this app goes away."),
    "com.android.deskclock": ("Clock", SAFE, "Clock, alarms, timer.", "Alarms set in it will not ring."),
    "com.android.calculator2": ("Calculator", SAFE, "Calculator.", "Only this app goes away."),
    "com.android.camera": ("Camera (old)", SAFE, "Camera app.", "No camera app; other apps may not be able to take photos."),
    "com.android.camera2": ("Camera", SAFE, "Camera app.", "No camera app; other apps may not be able to take photos."),
    "com.android.soundrecorder": ("Sound recorder", SAFE, "Voice recorder.", "Only this app goes away."),
    "com.android.contacts": ("Contacts", CAUTION, "Contacts app (on older phones also the dialer).",
                             "On phones, you may lose the dialer too."),
    "com.android.dialer": ("Phone", CAUTION, "Phone / dialer app.", "You can't make calls from it."),
    "com.android.mms": ("Messaging (SMS)", CAUTION, "Text message app.", "No SMS app unless you have another."),
    "com.android.messaging": ("Messaging (SMS)", CAUTION, "Text message app.", "No SMS app unless you have another."),
    "com.android.chrome": ("Chrome", SAFE, "Google Chrome browser.",
                           "Only the browser goes away. On Android 7-9 Chrome can also act as "
                           "WebView - keep 'Android System WebView' turned on if you do this."),

    # ------------------------------------------------------------------
    # Google framework - be careful
    # ------------------------------------------------------------------
    "com.google.android.gms": ("Google Play services", CAUTION,
                               "The big Google background service: Google sign-in, location, "
                               "push notifications for many apps, Find My Device, backups.",
                               "Most Google apps and many other apps break or lose "
                               "notifications. Android itself keeps running."),
    "com.google.android.gsf": ("Google Services Framework", CAUTION,
                               "Gives the device its Google ID and handles push-message registration.",
                               "Google account features and push notifications break."),
    "com.google.android.gsf.login": ("Google account login (old)", CAUTION,
                                     "Signs you into your Google account on older Android.",
                                     "You can't sign into Google."),
    "com.android.vending": ("Google Play Store", CAUTION,
                            "The app store; also updates apps and checks licences.",
                            "No app installs or updates; some paid apps refuse to open."),
    "com.google.android.ext.shared": ("Android Shared Library", CAUTION,
                                      "Shared code some apps rely on.",
                                      "Some apps may crash."),
    "com.google.android.location": ("Google network location (old)", CAUTION,
                                    "Wi-Fi/tower location on older Android.",
                                    "Location gets slower or stops."),
    "com.google.android.ims": ("Carrier Services", CAUTION,
                               "Helps with RCS chat, VoLTE and Wi-Fi calling.",
                               "RCS chat or Wi-Fi calling may stop."),
    "com.google.android.setupwizard": ("Setup wizard", CAUTION,
                                       "The screens you see when you first set up the device.",
                                       "Fine after setup on most devices, but on some the Home "
                                       "button stops working."),
    "com.google.android.syncadapters.contacts": ("Google Contacts sync", SAFE,
                                                 "Syncs contacts with your Google account.",
                                                 "Contacts stop syncing with Google."),
    "com.google.android.syncadapters.calendar": ("Google Calendar sync", SAFE,
                                                 "Syncs calendar events with your Google account.",
                                                 "Events stop syncing with Google."),
    "com.google.android.backuptransport": ("Google backup transport", SAFE,
                                           "Sends device backups to your Google account.",
                                           "No cloud backups."),
    "com.google.android.backup": ("Google backup (old)", SAFE,
                                  "Cloud backup on older Android.", "No cloud backups."),
    "com.google.android.configupdater": ("ConfigUpdater", SAFE,
                                         "Downloads small security/config list updates from Google.",
                                         "Those small updates stop arriving."),
    "com.google.android.feedback": ("Market Feedback Agent", SAFE,
                                    "Sends crash reports and feedback to Google.",
                                    "No crash reports are sent."),
    "com.google.android.partnersetup": ("Google Partner Setup", SAFE,
                                        "Maker/carrier customisations for Google apps.",
                                        "Nothing noticeable for most people."),
    "com.google.android.onetimeinitializer": ("One Time Init", SAFE,
                                              "Runs once on the very first start.", "Nothing noticeable."),
    "com.google.android.apps.restore": ("Restore", SAFE,
                                        "Restores apps and data during setup.", "Nothing after setup."),
    "com.google.android.apps.pixelmigrate": ("Data restore tool", SAFE,
                                             "Copies data from an old phone during setup.", "Nothing after setup."),
    "com.google.android.printservice.recommendation": ("Print service recommendation", SAFE,
                                                       "Suggests printer apps.", "No suggestions."),
    "com.google.android.tts": ("Speech services by Google", SAFE,
                               "Text-to-speech and voice typing.",
                               "Voice typing / read-aloud stop - keep it on if you use a screen reader."),
    "com.google.android.marvin.talkback": ("Accessibility Suite (TalkBack)", SAFE,
                                           "Screen reader and other accessibility tools.",
                                           "Keep it on if you rely on accessibility features."),
    "com.google.android.as": ("Android System Intelligence", SAFE,
                              "On-device smart features: Live Caption, smart text selection, "
                              "Now Playing.",
                              "Those smart features stop."),
    "com.google.android.as.oss": ("Private Compute Services", SAFE,
                                  "Helper for Android System Intelligence.",
                                  "Some smart features stop."),
    "com.google.android.apps.turbo": ("Device Health Services", SAFE,
                                      "Adaptive battery and battery-time estimates.",
                                      "Battery estimates get less accurate."),
    "com.google.android.inputmethod.latin": ("Gboard", CAUTION,
                                             "Google's keyboard.",
                                             "If it's your only keyboard you can't type anything."),
    "com.google.android.launcher": ("Google Now Launcher", CAUTION,
                                    "Home screen on older Nexus devices.",
                                    "If it's your only home screen the Home button does nothing."),
    "com.google.android.apps.nexuslauncher": ("Pixel Launcher", CAUTION,
                                              "Home screen on Pixel phones.",
                                              "If it's your only home screen the Home button does nothing."),
    "com.google.android.googlequicksearchbox": ("Google app", SAFE,
                                                "Google search, the Discover feed and 'Ok Google'.",
                                                "Search bar, feed and voice assistant stop. On old "
                                                "devices with Google Now Launcher the home screen "
                                                "depends on it - check that first."),
    "com.google.android.apps.googleassistant": ("Assistant", SAFE, "Shortcut app for Google Assistant.",
                                                "The shortcut goes away."),

    # Google user apps - safe
    "com.google.android.youtube": ("YouTube", SAFE, "YouTube app.", "Only this app goes away."),
    "com.google.android.apps.youtube.music": ("YouTube Music", SAFE, "Music streaming app.", "Only this app goes away."),
    "com.google.android.apps.youtube.kids": ("YouTube Kids", SAFE, "YouTube for children.", "Only this app goes away."),
    "com.google.android.music": ("Google Play Music", SAFE, "Old music app (Google closed the service in 2020).",
                                 "Only this app goes away."),
    "com.google.android.videos": ("Google TV / Play Movies", SAFE, "Movies and TV app.", "Only this app goes away."),
    "com.google.android.apps.books": ("Google Play Books", SAFE, "E-books and audiobooks.", "Only this app goes away."),
    "com.google.android.apps.magazines": ("Google News", SAFE, "News reader (formerly Play Newsstand).",
                                          "Only this app goes away."),
    "com.google.android.play.games": ("Google Play Games", SAFE, "Game hub; some games use it to save progress.",
                                      "Some games lose cloud saves / achievements."),
    "com.google.android.talk": ("Hangouts", SAFE, "Old chat app (discontinued).", "Only this app goes away."),
    "com.google.android.apps.plus": ("Google+", SAFE, "Old social network app (discontinued).", "Only this app goes away."),
    "com.google.android.apps.maps": ("Google Maps", SAFE, "Maps and navigation.", "Only this app goes away."),
    "com.google.android.gm": ("Gmail", SAFE, "Email app.", "Only this app goes away."),
    "com.google.android.gm.exchange": ("Exchange services (Gmail)", SAFE, "Work mail sync for Gmail (old).",
                                       "Exchange accounts stop syncing."),
    "com.google.android.apps.photos": ("Google Photos", SAFE, "Photo gallery and cloud backup.",
                                       "Photo backup to Google stops."),
    "com.google.android.apps.docs": ("Google Drive", SAFE, "Cloud file storage.", "Only this app goes away."),
    "com.google.android.apps.docs.editors.docs": ("Google Docs", SAFE, "Documents editor.", "Only this app goes away."),
    "com.google.android.apps.docs.editors.sheets": ("Google Sheets", SAFE, "Spreadsheets.", "Only this app goes away."),
    "com.google.android.apps.docs.editors.slides": ("Google Slides", SAFE, "Presentations.", "Only this app goes away."),
    "com.google.android.keep": ("Google Keep", SAFE, "Notes app.", "Only this app goes away."),
    "com.google.android.calendar": ("Google Calendar", SAFE, "Calendar app.", "Only this app goes away; events stay."),
    "com.google.android.contacts": ("Contacts (Google)", CAUTION, "Google's contacts app.",
                                    "On phones the dialer may depend on it."),
    "com.google.android.dialer": ("Phone (Google)", CAUTION, "Google's phone app.", "You can't make calls from it."),
    "com.google.android.apps.messaging": ("Messages (Google)", CAUTION, "Google's SMS app.",
                                          "No SMS app unless you have another."),
    "com.google.android.apps.tachyon": ("Google Meet (Duo)", SAFE, "Video calls.", "Only this app goes away."),
    "com.google.android.apps.wellbeing": ("Digital Wellbeing", SAFE, "Screen-time stats and limits.",
                                          "Screen-time features go away."),
    "com.google.android.projection.gearhead": ("Android Auto", SAFE, "Car screen integration.",
                                               "Android Auto stops working."),
    "com.google.android.apps.subscriptions.red": ("Google One", SAFE, "Google storage subscription app.",
                                                  "Only this app goes away."),
    "com.google.android.apps.walletnfcrel": ("Google Wallet", SAFE, "Payments and cards.", "Tap-to-pay with Google stops."),
    "com.google.android.apps.chromecast.app": ("Google Home", SAFE, "Controls Chromecast / smart home devices.",
                                               "Only this app goes away."),
    "com.google.ar.core": ("Google Play Services for AR", SAFE, "Augmented reality support.",
                           "AR features in apps stop."),
    "com.google.android.apps.nbu.files": ("Files by Google", SAFE, "File manager and cleaner.", "Only this app goes away."),
    "com.google.android.apps.fitness": ("Google Fit", SAFE, "Fitness tracking.", "Only this app goes away."),
    "com.google.android.apps.translate": ("Google Translate", SAFE, "Translator.", "Only this app goes away."),
    "com.google.android.apps.podcasts": ("Google Podcasts", SAFE, "Podcast player (discontinued).", "Only this app goes away."),
    "com.google.android.street": ("Street View", SAFE, "Street View app.", "Only this app goes away."),
    "com.google.android.apps.cloudprint": ("Cloud Print", SAFE, "Google Cloud Print (discontinued).",
                                           "Only this app goes away."),
    "com.google.android.apps.genie.geniewidget": ("News & Weather (old)", SAFE, "Old news/weather widget.",
                                                  "Only this app goes away."),
    "com.google.android.apps.currents": ("Google Currents (old)", SAFE, "Old news reader.", "Only this app goes away."),
    "com.google.android.ears": ("Sound Search (old)", SAFE, "Song recognition widget.", "Only this app goes away."),
    "com.google.android.apps.uploader": ("Picasa uploader (old)", SAFE, "Old photo uploader.", "Only this app goes away."),
    "com.google.android.apps.authenticator2": ("Google Authenticator", SAFE, "Two-step login codes.",
                                               "You can't see your login codes while it's off (they are not deleted)."),
    "com.google.android.apps.safetyhub": ("Personal Safety", SAFE, "Car-crash detection, emergency sharing.",
                                          "Those safety features stop."),
    "com.google.android.apps.photos.scanner": ("PhotoScan", SAFE, "Scans paper photos.", "Only this app goes away."),

    # Common pre-installed third-party services
    "com.facebook.appmanager": ("Facebook App Manager", SAFE,
                                "Pre-installed by some makers to install/update Facebook apps.",
                                "Facebook apps stop updating by themselves."),
    "com.facebook.services": ("Facebook Services", SAFE,
                              "Pre-installed Facebook background service.", "Nothing noticeable."),
    "com.facebook.system": ("Facebook App Installer", SAFE,
                            "Pre-installed Facebook installer.", "Nothing noticeable."),
    "com.netflix.partner.activation": ("Netflix activation", SAFE,
                                       "Maker deal helper for Netflix.", "Nothing noticeable."),
}

# Families of packages that share a prefix. First match wins, so put the
# more specific prefixes first.
PREFIX_RULES = [
    ("com.android.networkstack", CRITICAL,
     "Network stack: Wi-Fi/mobile connection checks and address setup (Android 10+).",
     "The device may lose all network connections."),
    ("com.google.android.networkstack", CRITICAL,
     "Network stack (Google version): connection checks and address setup.",
     "The device may lose all network connections."),
    ("com.android.internal.systemui.navbar.", CAUTION,
     "A navigation bar style (gestures / 2-button / 3-button).",
     "Turning off the style you use can leave you without navigation."),
    ("com.android.internal.display.cutout.", SAFE,
     "Screen-notch emulation (developer option).", "Nothing noticeable."),
    ("com.android.theme.", SAFE,
     "A system colour/icon/font style option.", "That style option disappears from Settings."),
    ("com.google.android.overlay.", CAUTION,
     "An 'overlay': it adjusts the look or settings of another system part.",
     "Usually harmless, but some carry carrier or device settings."),
    ("com.google.android.gms.", CAUTION,
     "A piece of Google Play services.",
     "Some Google Play services features may stop."),
    ("com.android.hotwordenrollment.", SAFE,
     "Voice training for 'Ok Google'.", "Voice training goes away."),
    ("com.android.cts.", SAFE,
     "Android compatibility-test helper.", "Nothing noticeable."),
    ("com.android.providers.", CAUTION,
     "A data store that other apps read from.",
     "Apps that use this data may break."),
    ("com.qualcomm.", CAUTION,
     "Qualcomm chip service - some handle mobile network, GPS, camera or audio.",
     "Depends on which one; some break calls, GPS or camera."),
    ("com.qti.", CAUTION,
     "Qualcomm chip service - some handle mobile network, GPS, camera or audio.",
     "Depends on which one; some break calls, GPS or camera."),
    ("org.codeaurora.", CAUTION,
     "Qualcomm (Code Aurora) system part.",
     "Depends on which one; some break calls, Bluetooth or Wi-Fi."),
    ("com.facebook.", SAFE,
     "Facebook component.", "Only Facebook features are affected."),
    ("com.samsung.", CAUTION, "Samsung system part.", "Depends on which one - look it up first."),
    ("com.sec.", CAUTION, "Samsung system part.", "Depends on which one - look it up first."),
    ("com.miui.", CAUTION, "Xiaomi (MIUI) system part.", "Depends on which one - look it up first."),
    ("com.xiaomi.", CAUTION, "Xiaomi system part.", "Depends on which one - look it up first."),
    ("com.huawei.", CAUTION, "Huawei system part.", "Depends on which one - look it up first."),
]

# Permission names -> what they let an app do, in plain words.
PERM_TEXT = {
    "android.permission.INTERNET": "use the internet",
    "android.permission.ACCESS_FINE_LOCATION": "know your exact location",
    "android.permission.ACCESS_COARSE_LOCATION": "know your rough location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "track location even when you're not using it",
    "android.permission.CAMERA": "use the camera",
    "android.permission.RECORD_AUDIO": "use the microphone",
    "android.permission.READ_CONTACTS": "read your contacts",
    "android.permission.WRITE_CONTACTS": "change your contacts",
    "android.permission.GET_ACCOUNTS": "see the accounts on the device",
    "android.permission.READ_SMS": "read your text messages",
    "android.permission.RECEIVE_SMS": "receive text messages",
    "android.permission.SEND_SMS": "send text messages",
    "android.permission.READ_CALL_LOG": "read your call history",
    "android.permission.CALL_PHONE": "make phone calls",
    "android.permission.READ_PHONE_STATE": "read the phone's identity and call status",
    "android.permission.READ_PHONE_NUMBERS": "read your phone number",
    "android.permission.READ_CALENDAR": "read your calendar",
    "android.permission.WRITE_CALENDAR": "change your calendar",
    "android.permission.READ_EXTERNAL_STORAGE": "read your files",
    "android.permission.WRITE_EXTERNAL_STORAGE": "change or delete your files",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "access all files on the device",
    "android.permission.READ_MEDIA_IMAGES": "see your photos",
    "android.permission.READ_MEDIA_VIDEO": "see your videos",
    "android.permission.READ_MEDIA_AUDIO": "see your music and audio files",
    "android.permission.BODY_SENSORS": "read body sensors (heart rate etc.)",
    "android.permission.ACTIVITY_RECOGNITION": "detect walking, driving and other activity",
    "android.permission.RECEIVE_BOOT_COMPLETED": "start by itself when the device turns on",
    "android.permission.SYSTEM_ALERT_WINDOW": "draw on top of other apps",
    "android.permission.REQUEST_INSTALL_PACKAGES": "install other apps",
    "android.permission.PACKAGE_USAGE_STATS": "see which apps you use and for how long",
    "android.permission.QUERY_ALL_PACKAGES": "see every app you have installed",
    "android.permission.BLUETOOTH_CONNECT": "connect to Bluetooth devices",
    "android.permission.BLUETOOTH_SCAN": "scan for nearby Bluetooth devices",
    "android.permission.NFC": "use NFC",
    "android.permission.USE_BIOMETRIC": "use your fingerprint / face check",
    "android.permission.POST_NOTIFICATIONS": "show notifications",
    "android.permission.WAKE_LOCK": "keep the device awake",
    "android.permission.CHANGE_WIFI_STATE": "turn Wi-Fi on/off and change networks",
    "android.permission.READ_LOGS": "read system logs",
    "android.permission.WRITE_SETTINGS": "change system settings",
    "android.permission.WRITE_SECURE_SETTINGS": "change protected system settings",
}

RISK_TEXT = {
    SAFE: "\u2705 Safe to turn off",
    CAUTION: "\u26a0 Be careful",
    CRITICAL: "\u26d4 Don't turn off",
    UNKNOWN: "\u2753 Not assessed",
}

RISK_SHORT = {SAFE: "\u2705 safe", CAUTION: "\u26a0 careful", CRITICAL: "\u26d4 keep on",
              UNKNOWN: "\u2753 unknown"}


def lookup(package):
    """Return dict(name, risk, what, if_off) from KNOWN or PREFIX_RULES, or None."""
    entry = KNOWN.get(package)
    if entry:
        name, risk, what, if_off = entry
        return {"name": name, "risk": risk, "what": what, "if_off": if_off, "exact": True}
    for prefix, risk, what, if_off in PREFIX_RULES:
        if package == prefix or package.startswith(prefix):
            return {"name": None, "risk": risk, "what": what, "if_off": if_off, "exact": False}
    return None


def guess(package, system, from_store=None, hidden=None):
    """Fallback risk + reason for packages not in the lists above.

    from_store: True if installed from a recognised app store, False if sideloaded
                (APK/ADB/unknown), None if not known.
    hidden:     True if the app has no launcher icon, None/False otherwise.
    The user-app case is deliberately NOT a blanket 'safe': a sideloaded or
    hidden app is user-installed too, and that's exactly what shouldn't be
    waved through. Turning an app OFF is still reversible and never deletes
    data, so the worst case here is caution, not critical."""
    p = package.lower()
    off_note = ("Turning an app OFF is reversible and doesn't delete it, but it can interrupt "
                "something that depends on it - a keyboard, launcher, VPN, accessibility service "
                "or another app - so check what it is first.")
    if not system:
        # Evidence, strongest indicator first. None of these are proof on their own;
        # the verdict reflects how much is known, and store origin is NOT a clean bill.
        if hidden is True and from_store is False:
            return CAUTION, ("Two things worth a look: it was installed from outside an app store, "
                             "and it has no icon in the app drawer. Each has innocent explanations "
                             "(plugins and keyboards have no icon; you may have sideloaded it on "
                             "purpose), but together they're worth checking in the Security tab "
                             "before you trust it. " + off_note)
        if from_store is False:
            return CAUTION, ("It was installed from an APK file or over ADB rather than through an "
                             "app store. That's normal for apps you sideloaded deliberately, but it "
                             "wasn't vetted by a store, so check it if you don't recognise it. "
                             + off_note)
        if hidden is True:
            return CAUTION, ("It has no icon in the app drawer. That's normal for keyboards, "
                             "plugins, widgets and some accessibility tools, but it's also a thing "
                             "worth confirming if you don't recognise the app. " + off_note)
        if from_store is True:
            return UNKNOWN, ("You installed this from an app store, which is the normal path - but a "
                             "store app can still be unwanted, compromised or depended on by "
                             "something else, so this tool can't call it safe by origin alone. "
                             "Use the Apps tab's AI lookup or the Security tab to learn what it is. "
                             + off_note)
        # origin genuinely unknown: say so plainly, don't guess either way
        return UNKNOWN, ("Not enough is known here to classify it: this app isn't in the built-in "
                         "list and its installation source couldn't be determined. That isn't a "
                         "red flag by itself - look it up (Apps tab > Ask AI) or check the Security "
                         "tab to see where it came from. " + off_note)
    if "provider" in p:
        return CAUTION, ("The name says 'provider' - that's usually a data store other apps "
                         "read from. Apps that use it may break.")
    if "overlay" in p:
        return CAUTION, ("The name says 'overlay' - it changes the look or settings of another "
                         "system part. Usually harmless, but operator overlays can affect mobile data.")
    if "launcher" in p:
        return CAUTION, "Looks like a home screen. Don't turn off the one you use."
    if "inputmethod" in p or "keyboard" in p:
        return CAUTION, "Looks like a keyboard. Don't turn off the one you use."
    return CAUTION, ("It came with the device and isn't in the built-in list. Look it up "
                     "online first - many of these are fine to turn off, some aren't.")
