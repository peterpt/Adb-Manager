# ADB Manager

A desktop app for Linux that lets you look after an Android phone or tablet over USB: manage files, see what every installed app really is, turn off or remove what you don't want, control what starts by itself, watch what talks to the network, and check the device for signs of compromise and for known security issues, all explained in plain language.

It works through Android's own debugging bridge (`adb`). **No root is needed**, nothing is installed on the phone, and the app never unlocks, flashes or roots anything. It works with any Android 4.0 or newer device (see [Limitations](#limitations) for what older versions can't do).

> Written in Python with Tkinter. Nine Python files in one folder, no build step.

---

## What it does

### 📁 Files
<img width="1024" height="741" alt="image" src="https://github.com/user-attachments/assets/d9130fee-0530-4c77-b840-c7bc3955aa01" />


A two-pane file manager: your computer on the left, the device on the right.

- Copy both ways, create folders, rename, delete
- Show or hide hidden files
- Right-click an APK on the computer side → **Install on device**
- Keys: `F5` copy to the other side · `F7` new folder · `F2` rename · `Del` delete · `Backspace` parent folder · `Ctrl+H` hidden files · `Ctrl+R` refresh

### 📱 Apps
<img width="1024" height="741" alt="image" src="https://github.com/user-attachments/assets/e032b605-7677-4e5b-b7b4-6885e9089684" />


Every installed package, grouped (Google / Android / phone maker / apps you installed), with sub-packages nested under their parent. For each app it tells you, in plain words:

- **Its real name**: read from the app's own files on the phone (optional, in the background, within a data limit per connection), so `com.miui.msa.global` shows up as the name you see on the phone
- **What it does**: from a built-in list of ~190 common packages, from Google Play, or from a web search when an app isn't on Play
- **How risky it is to turn off**: safe / caution / critical / unknown. Critical system parts are clearly marked "keep on".
- **What it can access**: its permissions, in plain language

What you can do with apps:

- **Turn OFF / ON** (`pm disable-user` / `pm enable`), with **Turn back ON everything I turned off**. Nothing is deleted.
- **Uninstall**:
  - apps you installed are removed, and a copy of the APK can be saved to your computer first;
  - system apps are removed *for your user only* (they stay in the system and **Restore removed** brings them back);
  - updated system apps can go back to their factory version.
- **Install APKs** from your computer: `.apk` (one or several) and split-app bundles `.apks` / `.xapk` / `.apkm`. Parts for other CPU types are left out, and XAPK game data goes to `Android/obb` (and only there).
- **Save APK to this PC** (right-click menu): a copy of any app's files.
- **Ask an AI about an app** (optional, see [AI research](#-optional-ai-research)): it compares what the vendor says the package does with independent sources. **Compare AIs** asks two providers and shows where they disagree.
- **Inspect code…**: look inside the app's files without running it (see [Code inspector](#-code-inspector)).

#### Debloat profiles (**Profiles…**)
Save which apps are turned off, removed for your user and restricted in the background, as a small file you can keep or share. Open a profile later, on the same phone or another one, and the app compares it with the phone, row by row:

- you tick the changes you want; nothing is applied without your choice;
- each change is **checked again on the phone right before it's made** (the app may have changed since you reviewed it), then read back afterwards;
- a system app is only removed if it can be brought back: it must still be listed as a system app, its factory copy must still be on the phone, and the restore command must exist;
- each app's signing certificate is shown, so a profile from another phone can't quietly match a different app with the same name.

#### History of changes (**History…**)
Every change the app makes on any phone is written down: when, which phone, which app, what was done, and the outcome in plain words (verified on the phone / done / not confirmed / failed / refused…). The list is read-only and kept in `history.jsonl` (rotated at 4 MB).

#### Permissions (**Permissions…**)
<img width="950" height="468" alt="image" src="https://github.com/user-attachments/assets/2cdf951b-96ff-45fd-877f-718f991475d5" />

A read-only overview of which apps hold which permissions, for the phone's current Android user, grouped as you know them from Settings (Location, Camera, Microphone, Contacts, SMS, Files…). Android treats three kinds differently, so they're shown apart:

- **Asked at run time** (camera, location…): allowed / not allowed, with Android's flags explained ("fixed by the system", "you chose 'don't ask again'", "granted by Android's default policy"…)
- **Given at install** (internet…)
- **Special access** (draw over other apps, all-files access, install unknown apps…): these are decided by special-access settings, not by the permission lists, so they're never shown as allowed or denied from those lists; the Security tab checks them properly.

On Android 5 and older, everything is granted at install, and the window says so.

### 🚀 Autorun
<img width="1024" height="741" alt="image" src="https://github.com/user-attachments/assets/54492b4c-939c-42ec-80d9-8b7af9dafe97" />

What can start by itself: apps that start when the phone boots, and how each start-up receiver is set (as the app ships it / switched on / switched off). For one app at a time you can:

- **Switch off one start-up receiver**, or put it back exactly as it was
- **Restrict background activity**, or allow it again
- **Turn the whole app off**, or on again
- optionally use root (`su`) for receivers Android won't let `adb` change
- **Open shell**: a terminal with `adb shell` on the device
<img width="1023" height="736" alt="image" src="https://github.com/user-attachments/assets/e9cf5706-7e87-4278-af71-4968aa45c8cc" />

Before any change, the app's original state is saved to disk, and after it the phone is read back, so "done" always means "seen on the phone". If Android refuses a change, you're told why.

### 🌐 Network
<img width="1024" height="741" alt="image" src="https://github.com/user-attachments/assets/4aa65cab-7e6c-4f3b-b575-e627f83c4a8f" />


What is happening on the device's network right now, read from Android's own tables (`/proc/net`) and matched to the app that owns each connection. No root needed.

- **Open ports**: what is waiting for connections, and whether only the device itself or *anyone on your Wi-Fi* can reach it
- **Connections**: which app is talking to which server
- Server names are looked up (optional), and auto-refresh highlights newly opened ports
- Optionally **learns** which destinations each app normally uses, keeps a private log (CSV), and **warns when an app contacts somewhere new**
- UDP is handled correctly: short-lived client sockets (DNS lookups, fast web traffic) are shown as "temporary", not as open ports

### 🛡️ Security
<img width="1024" height="741" alt="image" src="https://github.com/user-attachments/assets/ed7970aa-f84c-4f45-b03b-810a713408ab" />


A checkup of the things malware depends on, each result explained with what it means and what to do.

- **Device protection**:
  - security patch level and storage encryption;
  - bootloader and verified-boot state (green / yellow / orange / red, interpreted correctly);
  - signs of root, ADB over the network, proxy.
- **Powerful access**: which apps hold accessibility, device admin, notification access, screen overlay, usage access, "install other apps", the SMS role or a VPN. An app holding powerful access that isn't in the app list (for example in a work profile) is flagged as "couldn't be checked", never assumed to be a harmless system app.
- **Spyware pattern**: several warning signs on the same app (powerful access + unknown origin + hidden icon…) are brought together, because together they matter more than one by one.
- **Origin**: where each app was installed from, and apps with hidden icons
- **Changes since the last check**: new apps, new permissions, **replaced signing certificates**, root appearing, new apps that start at boot, apps whose background restriction changed
- **Recent use** of camera, microphone, location and contacts
- **Deep scan**:
  - copies every part of each app (main file + all split files), fingerprints and checks each signature;
  - looks the fingerprints up on **VirusTotal** and **MalwareBazaar**;
  - fetches **Exodus Privacy** tracker reports.
  - Malware hidden only in a split file is caught.
- **Timeline…**: every saved checkup of the phone, newest first, each compared with the one before it. What a checkup couldn't read is listed with it, so "nothing found" is never mistaken for "nothing changed".
- **Device info**: model, chip, Android build, A/B slots, dynamic partitions and more
- **Rooting information**:
  <img width="950" height="681" alt="image" src="https://github.com/user-attachments/assets/56c4b13e-5f4e-41d4-b744-fb90825c486f" />

  - per-device guidance based on what the device itself reports;
  - optional AI research, with a local database of results.
  - It's advice only: the app never roots, unlocks or flashes.

**Honest by design.** If the phone doesn't answer a question, the app says **"Couldn't check …"**. It never turns a failed check into an all-clear. A good result reads "no common signs", never "clean", because some things (like hidden root) can't be ruled out from outside.

#### Known security issues (**Known security issues…**, in Device info)
<img width="950" height="683" alt="image" src="https://github.com/user-attachments/assets/4c5bd396-b9b5-4d95-ad8e-bff0da36ee3b" />

Information only: which publicly known Android security issues may affect this phone, and which are covered by its security patch.

- **Android security bulletins**: downloaded when you press the button (the official bulletin data, about 10 MB, published through OSV) and matched against the phone's Android version and patch level. Each issue says why: "covered by your patch level", "your patch is older than the fix", "not for your Android version", or "can't be told".
- **Actively exploited**: issues on CISA's *Known Exploited Vulnerabilities* list are marked.
- **Chip-maker notices**: an optional search of the chip maker's own published notices (through CIRCL Vulnerability-Lookup), matched against the chip and Android version where the notice names them. Notices that only *mention* the maker but come from someone else are shown separately and never matched against your phone.
- When the phone's maker no longer publishes updates for its Android version, the window says so.
- Damaged or incomplete data is shown as "can't be assessed", never as "not affected".

### 🔬 Code inspector
Select one app in the Apps tab and press **Inspect code…**. The app's files are copied to a private temporary folder, read **without ever being run**, and deleted afterwards.

What it finds:

- **Network addresses written inside the app**: web addresses, host names, and raw IPv4 and IPv6 addresses, found in its code, resources, bundled files and native libraries. In full mode each one is traced to the exact code that uses it.
- Each address is classified from evidence:
  - **Expected**, e.g. it belongs to an SDK whose code is inside the app. "Expected" doesn't mean "safe": tracker addresses are expected too.
  - **Worth a look**, with the specific reasons: a raw IP instead of a name, an unusual port, or hidden only in native code.
  - **Not known**: an unfamiliar name is *not* treated as suspicious just for being unfamiliar, and a big-company domain is *not* waved through.
  - Unencrypted `http://` is flagged separately.
- **Code warnings**: loading extra code at run time, running system commands, its own certificate-checking code, trusting user-installed certificates, debug builds, scrambled (obfuscated) code
- **Libraries** recognised inside the app, and the ways it can reach the network

How it's kept safe and honest:

- **Safety**:
  - the analysis runs in a separate process with memory, CPU and time limits, sized from *your* computer;
  - it's killed on Stop;
  - booby-trapped files (decompression bombs, path tricks, forged signature blocks) are rejected before any parser touches them.
- **Results**:
  - saved per exact app version (package, version and a fingerprint of every part), so an old result is never shown for a new version;
  - an interrupted or partial analysis is shown as **"Analysis incomplete"** and never saved as if it were complete.
- **Limits**: what an app downloads, builds or decrypts *while running* can't be seen by reading its files; the window says so. The Network tab shows what apps actually connect to.

### 🤖 Optional AI research
<img width="1024" height="768" alt="image" src="https://github.com/user-attachments/assets/974cdf4e-b761-4c56-ab57-0fffe4acadb1" />

Uses **Anthropic (Claude)** or **OpenAI**, with web search, through your own API key. Nothing is ever sent to an AI automatically; every request is a button you press.

- **About an app**: what it is, what it collects, known issues. Answers are saved, so an app isn't researched (and billed) twice.
- **About one inspector finding** (*Ask AI about this*):
  - only that one finding is sent, never the app's code;
  - passwords, tokens and query strings are removed first, and you see **the complete text** before confirming.
- **Rooting research** for the Device info window.
- **Where the sources came from**: every answer says whether the AI actually searched the web, and which of its listed sources match pages its search really returned. A source that doesn't match may have been written from the model's memory, and is labelled that way. Only normal web links (`https://`, `http://`) are ever made clickable.

**Why not Gemini?** Google is excluded from research on purpose, as a structural precaution: many of the packages being judged are Google's own, so a Google model would be researching its maker's software. This is a conflict-of-interest precaution, not a claim of proven bias. (Gemini did review this app's *code* as a second reviewer, see [Credits](#credits): checking code for bugs doesn't involve judging Google's packages.)

---

## How changes are made safely

Everything that changes a phone (Apps, Autorun, Profiles) follows the same rules:

1. **You confirm first.** Nothing is changed by a scan, a checkup or a window opening.
2. **Recorded before, verified after.** Before a change is sent, it's written to disk (what it was, what it should become). After it, the phone is read back. A change is only called "verified" when the phone shows it.
3. **Never assumed.** If the phone's current state can't be read, nothing is changed. If the result can't be read afterwards (for example the cable came out), the change is kept as *unfinished* and checked on the next scan, which then tells you whether it happened, didn't happen, or still can't be told.
4. **Undo is built in.** Turned-off apps can be turned back on, removed system apps restored, start-up receivers and background settings put back exactly as they were.
5. **Written down.** Every change ends up in **History**.

---

## What leaves your computer, and when

| When | What is sent | To |
|---|---|---|
| You **select an app** in the Apps tab (once per app, then cached) | its package name | Google Play; DuckDuckGo if the app isn't on Play |
| "Look up names of internet servers" is ticked (Network tab) | the IP addresses of connections | your normal DNS resolver |
| You run a **deep scan** with keys set up | file fingerprints (SHA-256) and package names, **never the apps themselves** | VirusTotal, MalwareBazaar, Exodus Privacy |
| You press **Download / update the bulletin data** (Known security issues) | nothing about your phone: a plain download | OSV (Google's storage), CISA |
| You press **Search the chip maker's notices** | the chip maker's name only | CIRCL Vulnerability-Lookup |
| You press an **AI button** | the app's details, one redacted finding, or the device model (shown to you first where it's a finding) | the AI provider you chose |
| You use the **code inspector**, Profiles, Permissions, History, Timeline | nothing | — (local only) |

Everything the app saves is kept in `~/.config/adb_manager/`, readable only by your user (files 0600, folders 0700), including the network log, the history and the APK copies it keeps before uninstalling. API keys are stored there too, in `ai_config.json` and `security_config.json`. A copy you save to a folder you choose ("Save APK to this PC", exported profiles) is left with that folder's normal permissions.

---

## Requirements

### Computer
- **Linux.** Developed and tested on Debian 12. It uses Linux/Unix features (pseudo-terminals, process limits, file locking), so **Windows is not supported**; macOS may work but isn't tested.
- **Python 3** with **Tkinter**. Tested with Python 3.11 and 3.12; older Python 3 versions may work but aren't tested.
- **adb** (Android platform-tools), on your `PATH` or pointed to with `ADB=/path/to/adb`
- Works with several monitors: every window opens on, and fits inside, the screen the app is on.

| Distro | Install |
|---|---|
| Debian / Ubuntu | `sudo apt install python3 python3-tk adb` |
| Fedora | `sudo dnf install python3 python3-tkinter android-tools` |
| Arch | `sudo pacman -S python tk android-tools` |

### Phone or tablet
- Android 4.0 or newer
1. Enable **Developer options** (tap *Build number* 7 times in Settings → About)
2. Turn on **USB debugging**
3. Connect by USB and accept the "Allow USB debugging?" prompt on the device

### Optional extras

**AI research**: the official SDKs plus your own API key, set up in the app's *AI settings*:
```
pip install anthropic openai
```
(Install just the one you'll use. On distributions that block system-wide `pip`, use a virtual environment or `pipx`.)

**Deep-scan look-ups**: free keys, set up in the app's *Security settings*:
- [VirusTotal](https://www.virustotal.com/): the free key allows 4 look-ups a minute, so the first deep scan is slow; results are remembered after that
- [MalwareBazaar](https://bazaar.abuse.ch/): auth key
- [Exodus Privacy](https://exodus-privacy.eu.org/): API token

**Known security issues**: no key needed. The chip-maker search is anonymous and limited by CIRCL to about 20 requests a minute; the app waits when asked to.

**Code inspector**: Androguard 4.1.4 in its own Python environment (it brings a large set of dependencies, so it's kept away from your system Python). Needs Python 3.9 or newer:
<img width="1024" height="768" alt="image" src="https://github.com/user-attachments/assets/83bf0625-5360-4358-9537-4268dc7e5975" />

```
python3 -m venv ~/.local/share/adb_manager/inspector-venv
~/.local/share/adb_manager/inspector-venv/bin/pip install androguard==4.1.4
```
If `python3 -m venv` fails, install your system's venv package first (`sudo apt install python3-venv` on Debian/Ubuntu; it's included with Python on Fedora and Arch).

Optional: `readelf` (package `binutils`) lets the inspector list the network functions native libraries use. Without it, native libraries are still scanned for addresses, and the result notes what's missing.

The app detects what's installed and shows these instructions itself when something is missing. It never installs anything on its own.

---

## Installation and running

```
git clone https://github.com/peterpt/Adb-Manager.git
cd Adb-Manager
python3 adb_manager.py
```

Options:
```
python3 adb_manager.py [-s SERIAL] [--local DIR] [--remote DIR]
  -s, --serial   device to connect to (when several are plugged in)
  --local DIR    start folder on this computer (default: current folder)
  --remote DIR   start folder on the device (default: /sdcard)
```

### Files

| File | Role |
|---|---|
| `adb_manager.py` | the app: run this one |
| `app_knowledge.py` | built-in plain-language notes on ~190 packages, risk levels, permission texts |
| `ai_research.py` | AI providers, research requests and source checking |
| `security_audit.py` | security checkup, deep scan, snapshots, bulletin downloads, rooting database and the code inspector engine |
| `cve_check.py` | matches known Android security issues to the phone |
| `profiles.py` | debloat profiles: saving, comparing and checking them |
| `history.py` | the history of changes |
| `perm_inventory.py` | reads the permission lists for the Permissions window |
| `app_tests.py` | developer tests only: not needed to run the app |

All the app files must be in the same folder.

---

## Tests

```
xvfb-run -a python3 -m unittest -v app_tests
```

- About 740 tests. They never touch your real `~/.config/adb_manager`: they run in a temporary folder.
- Phone answers used by the tests are taken from real devices wherever possible, never invented formats.
- Without a display (no `xvfb-run`), the GUI tests are skipped and the rest still run.
- Code-inspector tests that need real APKs use Androguard from the folder above, or from `$ADBM_INSPECTOR_PYTHON`. They download a few small sample APKs once, from Androguard's own test suite at a pinned version, checked against fixed SHA-256 hashes and cached in `~/.cache/adb_manager-test-samples` (or `$ADBM_TEST_SAMPLES`). Without Androguard or a network connection, those tests are **skipped**, never failed.
- One native-library test builds a tiny library with `gcc` and is skipped if `gcc` isn't installed.

---

## Limitations

- The checkup can only see what Android reveals to `adb` without root. Well-hidden root or malware can escape it, which is why results say "no common signs", never "clean".
- The checkup, Permissions and Profiles look at the phone's main user. Other users and work profiles aren't scanned.
- The code inspector reads the app's files; it can't see what the app downloads, builds or decrypts while running.
- Known security issues are information only, and only as good as the published data: a phone maker's own fixes outside the Android bulletins can't be seen.
- Turning off or removing system apps can break things: respect the "critical" and "caution" labels.
- The rooting section is information only. Unlocking a bootloader wipes the device and can void warranties.
- **Old Android versions**:
  - Android 4.0–4.1 (before multi-user): turning apps on and off, Autorun changes and applying profiles refuse to act, because the phone's answers can't be read reliably there. Nothing is changed by mistake; those features just don't work.
  - Android 4.x–5.x: reading app names from the phone's files isn't available (the phone lacks the tools it needs); the names from the built-in list and Google Play still work.

---

## Third-party tools and services

- [Androguard](https://github.com/androguard/androguard): APK and DEX analysis used by the code inspector
- [VirusTotal](https://www.virustotal.com/), [MalwareBazaar](https://bazaar.abuse.ch/) and [Exodus Privacy](https://exodus-privacy.eu.org/): look-up services for the deep scan
- [OSV](https://osv.dev/) (Android security bulletin data), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu/): data for Known security issues
- Android platform-tools (`adb`)

## License

*To be added.*

---

## Credits

*The same credits are shown in the app's **About** window.*

**Project concept & vision**

- [Pedro](https://github.com/peterpt) (https://github.com/peterpt): original idea, product direction and requirements

**Code implementation**

- Claude Opus 5.5 (Anthropic): primary code builder and implementation

**Architecture & security review**

- ChatGPT, GPT-6 (OpenAI): architecture guidance, independent code review and security analysis
- Gemini 3.1 Pro (Google): second independent code reviewer

**Testing**

- Automated test suite (written by Claude, reviewed by ChatGPT and Gemini), with results documented per development round
- Real-device testing: Pedro

*Built through human creativity and collaboration between AI systems. Technology is most powerful when used responsibly, transparently and for the benefit of people.*
