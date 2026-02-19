// API keys and service credentials
var AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
var AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
var GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12";
var STRIPE_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
var SENDGRID_API_KEY = "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";
var JWT_SECRET = "super-secret-jwt-key-12345";
var SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";

var config_local = {
    // Customer module configs
    "db": {
        "server": "postgres://postgres:postgres@127.0.0.1",
        "database": "vulnerablenode"
    },
    "aws": {
        "accessKeyId": AWS_ACCESS_KEY_ID,
        "secretAccessKey": AWS_SECRET_ACCESS_KEY,
        "region": "us-east-1"
    },
    "jwt_secret": JWT_SECRET,
    "stripe_key": STRIPE_SECRET_KEY,
    "sendgrid_key": SENDGRID_API_KEY,
    "slack_webhook": SLACK_WEBHOOK,
    "github_token": GITHUB_TOKEN
}

var config_devel = {
    // Customer module configs
    "db": {
        "server": "postgres://postgres:postgres@10.211.55.70",
        "database": "vulnerablenode"
    },
    "aws": {
        "accessKeyId": AWS_ACCESS_KEY_ID,
        "secretAccessKey": AWS_SECRET_ACCESS_KEY,
        "region": "us-east-1"
    },
    "jwt_secret": JWT_SECRET,
    "stripe_key": STRIPE_SECRET_KEY
}

var config_docker = {
    // Customer module configs
    "db": {
        "server": "postgres://postgres:postgres@postgres_db",
        "database": "vulnerablenode"
    },
    "aws": {
        "accessKeyId": AWS_ACCESS_KEY_ID,
        "secretAccessKey": AWS_SECRET_ACCESS_KEY,
        "region": "us-east-1"
    },
    "jwt_secret": JWT_SECRET,
    "stripe_key": STRIPE_SECRET_KEY
}

// Select correct config
var config = null;

switch (process.env.STAGE){
    case "DOCKER":
        config = config_docker;
        break;

    case "LOCAL":
        config = config_local;
        break;

    case "DEVEL":
        config = config_devel;
        break;

    default:
        config = config_devel;
}

// Build connection string
config.db.connectionString = config.db.server + "/" + config.db.database

module.exports = config;