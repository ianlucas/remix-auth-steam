/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Ian Lucas. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * A correct and simple implementation of OpenID authentication for Steam.
 * @see https://github.com/xPaw/SteamOpenID.php
 */
export class SteamOpenID {
    private static readonly SERVER = "https://steamcommunity.com/openid/login";
    private static readonly OPENID_NS = "http://specs.openid.net/auth/2.0";
    private static readonly EXPECTED_SIGNED =
        "signed,op_endpoint,claimed_id,identity,return_to,response_nonce,assoc_handle";
    private static readonly STEAM_ID_REGEX = /^https:\/\/steamcommunity\.com\/openid\/id\/(76561[0-9]{12})\/?$/;

    /**
     * The URL to which Steam will redirect the user after authentication.
     * This is also used to validate the "openid.return_to" parameter.
     */
    public readonly returnUrl: string;

    /**
     * The search parameters from the incoming request URL.
     */
    private readonly params: URLSearchParams;

    /**
     * Creates an instance of the SteamOpenID authenticator.
     * @param returnUrl The URL to which Steam should return. Must match the "openid.return_to" parameter on callback.
     * @param request The incoming web request object.
     */
    constructor(returnUrl: string, request: Request) {
        if (!returnUrl || !request) {
            throw new Error("Both returnUrl and request objects are required.");
        }
        this.returnUrl = returnUrl;
        this.params = new URL(request.url).searchParams;
    }

    /**
     * Returns `true` if the request URL contains the necessary parameters to be validated.
     * This indicates the user has been redirected back from Steam.
     */
    public shouldValidate(): boolean {
        return this.params.get("openid.mode") === "id_res";
    }

    /**
     * Gets the Steam authentication URL to redirect the user to.
     * @returns The authentication URL.
     */
    public getAuthUrl(): string {
        const params = new URLSearchParams({
            "openid.ns": SteamOpenID.OPENID_NS,
            "openid.mode": "checkid_setup",
            "openid.return_to": this.returnUrl,
            "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select"
        });
        return `${SteamOpenID.SERVER}?${params.toString()}`;
    }

    /**
     * Validates the authentication request from Steam.
     * @returns A `Promise` that resolves with the user's 64-bit SteamID.
     * @throws An `Error` if validation fails at any step.
     */
    public async validate(): Promise<string> {
        const args = this.getAndValidateArguments();

        // Verify that the request came from the Steam endpoint and matches our parameters
        if (args["openid.op_endpoint"] !== SteamOpenID.SERVER) {
            throw new Error('Invalid "openid.op_endpoint".');
        }
        if (!args["openid.return_to"]?.startsWith(this.returnUrl)) {
            throw new Error('Invalid "openid.return_to".');
        }

        // Validate response_nonce format and timestamp
        // RFC3339 YYYY-MM-DDTHH:MM:SSZ followed by unique characters
        const nonceMatch = args["openid.response_nonce"]?.match(
            /^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)/
        );
        if (!nonceMatch || !nonceMatch[1]) {
            throw new Error('Invalid "openid.response_nonce" format.');
        }

        const nonceTime = new Date(nonceMatch[1]).getTime();
        if (isNaN(nonceTime) || Math.abs(Date.now() - nonceTime) > 300_000) {
            throw new Error("Nonce timestamp is too old or invalid.");
        }

        // Extract SteamID from the identity URL
        const match = args["openid.identity"]?.match(SteamOpenID.STEAM_ID_REGEX);
        if (!match || !match[1]) {
            throw new Error('Invalid "openid.identity".');
        }
        const steamId = match[1];

        // Prepare parameters for server-side verification
        const verificationParams = new URLSearchParams(args);
        verificationParams.set("openid.mode", "check_authentication");

        // Make the verification request to Steam
        const response = await this.sendVerificationRequest(verificationParams);

        // Parse Steam's key-value response
        const keyValues = SteamOpenID.parseKeyValues(response);

        // Check if Steam confirmed the validation
        if (keyValues["is_valid"] !== "true" || keyValues["ns"] !== SteamOpenID.OPENID_NS) {
            throw new Error("Failed to validate login with Steam: Invalid response.");
        }

        return steamId;
    }

    /**
     * Sends the verification request to the Steam server.
     * Can be overridden for custom request logic (e.g., using a proxy).
     * @param params The parameters to send in the POST body.
     * @returns The response body as a string.
     */
    protected async sendVerificationRequest(params: URLSearchParams): Promise<string> {
        const response = await fetch(SteamOpenID.SERVER, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "TypeScript-SteamOpenID/1.0.0"
            },
            body: params
        });

        if (!response.ok) {
            if (response.status === 403 || response.status === 429) {
                throw new Error("Steam OpenID endpoint is rate-limited. Please try again later.");
            }
            throw new Error(`Steam verification request failed with HTTP ${response.status}.`);
        }

        return response.text();
    }

    /**
     * Retrieves required OpenID arguments from the request's query parameters
     * and performs initial validation.
     */
    private getAndValidateArguments(): Record<string, string> {
        const args: Record<string, string> = {};
        const signedKeys = SteamOpenID.EXPECTED_SIGNED.split(",");

        for (const key of signedKeys) {
            // The 'openid.' prefix is implicit for keys in EXPECTED_SIGNED
            const openIdKey = `openid.${key}`;
            const value = this.params.get(openIdKey);
            if (!value) {
                throw new Error(`Missing required OpenID parameter: "${openIdKey}".`);
            }
            args[openIdKey] = value;
        }

        // Add other required fields not in the 'signed' list
        const otherRequiredKeys = ["openid.mode", "openid.sig", "openid.ns"];
        for (const key of otherRequiredKeys) {
            const value = this.params.get(key);
            if (!value) {
                throw new Error(`Missing required OpenID parameter: "${key}".`);
            }
            args[key] = value;
        }

        if (args["openid.mode"] !== "id_res") {
            throw new Error('Invalid "openid.mode". Expected "id_res".');
        }
        if (args["openid.ns"] !== SteamOpenID.OPENID_NS) {
            throw new Error('Invalid "openid.ns".');
        }
        if (args["openid.signed"] !== SteamOpenID.EXPECTED_SIGNED) {
            throw new Error('Invalid "openid.signed" field.');
        }

        return args;
    }

    /**
     * Parses a Key-Value response string from Steam.
     */
    private static parseKeyValues(response: string): Record<string, string> {
        const data: Record<string, string> = {};
        const lines = response.trim().split("\n");
        for (const line of lines) {
            const separatorIndex = line.indexOf(":");
            if (separatorIndex !== -1) {
                const key = line.substring(0, separatorIndex);
                const value = line.substring(separatorIndex + 1);
                data[key] = value;
            }
        }
        return data;
    }
}
