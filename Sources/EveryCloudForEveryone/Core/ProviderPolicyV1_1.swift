import Foundation

public enum ProviderPolicyV1_1 {
    public static let blocked: Set<String> = [
        "Google", "Meta", "Mistral", "Cohere", "Perplexity", "Together", "Fireworks", "Groq", "AWS", "Azure", "Vercel"
    ]

    public static let allowed: Set<String> = [
        "xAI", "Local", "OpenAI", "Anthropic", "Custom", "iCloud", "Dropbox", "Box", "OneDrive", "pCloud",
        "Mega", "Proton", "Sync.com", "Wasabi", "Backblaze", "Storj", "Cloudflare R2", "Oracle", "IBM", "Alibaba", "Tencent"
    ]

    public static func allows(_ provider: String) -> Bool {
        allowed.contains(provider) && !blocked.contains(provider)
    }
}
