const clientId = "294d90e37e7d4fbb847ebb2462b338e8"; // Replace with your client id
const params = new URLSearchParams(window.location.search);
const code = params.get("code");

if (!code) {
    redirectToAuthCodeFlow(clientId);
} else {
    const accessToken = await getAccessToken(clientId, code);
    const [profile, playbackInfo] = await Promise.all([fetchProfile(accessToken), getPlaybackInfo(accessToken)]);
    populateUI(profile, playbackInfo);
}

export async function redirectToAuthCodeFlow(clientId: string) {
    const verifier = generateCodeVerifier(128);
    const challenge = await generateCodeChallenge(verifier);

    localStorage.setItem("verifier", verifier);

    const params = new URLSearchParams();
    params.append("client_id", clientId);
    params.append("response_type", "code");
    params.append("redirect_uri", "http://localhost:5173/callback");
    params.append("scope", "user-read-private user-read-email user-read-playback-state user-modify-playback-state");
    params.append("code_challenge_method", "S256");
    params.append("code_challenge", challenge);

    document.location = `https://accounts.spotify.com/authorize?${params.toString()}`;
}

function generateCodeVerifier(length: number) {
    let text = '';
    let possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    for (let i = 0; i < length; i++) {
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
}

async function generateCodeChallenge(codeVerifier: string) {
    const data = new TextEncoder().encode(codeVerifier);
    const digest = await window.crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode.apply(null, [...new Uint8Array(digest)]))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

export async function getAccessToken(clientId: string, code: string): Promise<string> {
    const verifier = localStorage.getItem("verifier");

    const params = new URLSearchParams();
    params.append("client_id", clientId);
    params.append("grant_type", "authorization_code");
    params.append("code", code);
    params.append("redirect_uri", "http://localhost:5173/callback");
    params.append("code_verifier", verifier!);

    const result = await fetch("https://accounts.spotify.com/api/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params
    });

    const { access_token } = await result.json();
    localStorage.setItem("access_token", access_token); // Store access token for later use
    return access_token;
}

async function getPlaybackInfo(token: string): Promise<PlaybackInfo> {
    try {
        const result = await fetch("https://api.spotify.com/v1/me/player", {
            method: "GET",
            headers: { Authorization: `Bearer ${token}` }
        });

        if (!result.ok) {
            throw new Error(`Failed to fetch playback info. Status: ${result.status}`);
        }

        return await result.json();
    } catch (error) {
        console.error("Error fetching playback info:", error);
        throw error; // rethrow the error for further handling
    }
}

async function startPlayback(token: string) {
    const result = await fetch("https://api.spotify.com/v1/me/player/play", {
        method: "PUT",
        headers: { Authorization: `Bearer ${token}` }
    });

    if (result.status === 204) {
        console.log("Playback started");
    } else {
        console.error("Failed to start playback");
    }
}

async function pausePlayback(token: string) {
    const result = await fetch("https://api.spotify.com/v1/me/player/pause", {
        method: "PUT",
        headers: { Authorization: `Bearer ${token}` }
    });

    if (result.status === 204) {
        console.log("Playback paused");
    } else {
        console.error("Failed to pause playback");
    }
}

export async function togglePlayback() {
    const token = localStorage.getItem("access_token");

    if (!token) {
        console.error("Access token not found. User may not be authenticated.");
        return;
    }

    const playbackInfo = await getPlaybackInfo(token);

    if (playbackInfo.is_playing) {
        await pausePlayback(token);
    } else {
        await startPlayback(token);
    }

    // After toggling playback, update the UI
    const updatedPlaybackInfo = await getPlaybackInfo(token);
    const profile = await fetchProfile(token);
    populateUI(profile, updatedPlaybackInfo);
}

export async function fetchProfile(token: string): Promise<UserProfile> {
    const result = await fetch("https://api.spotify.com/v1/me", {
        method: "GET", headers: { Authorization: `Bearer ${token}` }
    });

    return await result.json();
}

interface UserProfile {
    country: string;
    display_name: string;
    email: string;
    explicit_content: {
        filter_enabled: boolean,
        filter_locked: boolean
    },
    external_urls: { spotify: string; };
    followers: { href: string; total: number; };
    href: string;
    id: string;
    images: Image[];
    product: string;
    type: string;
    uri: string;
}

interface PlaybackInfo {
    is_playing: boolean;
    // Add other relevant playback information as needed
}

interface Image {
    url: string;
    height: number;
    width: number;
}

function populateUI(profile: UserProfile, playbackInfo: PlaybackInfo) {
    document.getElementById("displayName")!.innerText = profile.display_name;
    if (profile.images[0]) {
        const profileImage = new Image(200, 200);
        profileImage.src = profile.images[0].url;
        document.getElementById("avatar")!.appendChild(profileImage);
    }
    document.getElementById("id")!.innerText = profile.id;
    document.getElementById("email")!.innerText = profile.email;
    document.getElementById("uri")!.innerText = profile.uri;
    document.getElementById("uri")!.setAttribute("href", profile.external_urls.spotify);
    document.getElementById("url")!.innerText = profile.href;
    document.getElementById("url")!.setAttribute("href", profile.href);
    document.getElementById("imgUrl")!.innerText = profile.images[0]?.url ?? '(no profile image)';

    const playbackButton = document.getElementById("playbackButton") as HTMLButtonElement;
    if (playbackInfo.is_playing) {
        playbackButton.innerText = "Pause Playback";
    } else {
        playbackButton.innerText = "Resume Playback";
    }
    playbackButton.disabled = false; // Enable the button
}