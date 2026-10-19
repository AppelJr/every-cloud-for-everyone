/// Cloud providers supported by the enforcement layer.
public enum CloudProvider: String, CaseIterable, Sendable {
    // Consumer clouds
    case iCloud = "iCloud"
    case googleDrive = "Google Drive"
    case oneDrive = "OneDrive"
    case dropbox = "Dropbox"
    case mega = "MEGA"
    case pCloud = "pCloud"
    case syncCom = "Sync.com"

    // Enterprise / infrastructure clouds
    case awsS3 = "AWS S3"
    case azureBlob = "Azure Blob"
    case googleCloudStorage = "Google Cloud Storage"
    case backblazeB2 = "Backblaze B2"
    case wasabi = "Wasabi"
    case cloudflareR2 = "Cloudflare R2"
    case digitalOceanSpaces = "DigitalOcean Spaces"

    // Self-hosted / privacy-first
    case nextcloud = "Nextcloud"
    case box = "Box"
    case spiderOak = "SpiderOak"
    case tresorit = "Tresorit"
    case protonDrive = "Proton Drive"
    case filen = "Filen"

    // Other infrastructure
    case oracleCloud = "Oracle Cloud"
    case ibmCloud = "IBM Cloud"
    case alibabaCloud = "Alibaba Cloud"
    case tencentCloud = "Tencent Cloud"
}
