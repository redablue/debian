#!/bin/bash
# =============================================================================
# Script d'Installation Automatisée - Fidaous Pro
# Système : Debian 12 (Bookworm)
# Base de données : MariaDB
# Serveur Web : Apache2 + PHP 8.2
# Destination : /var/www/html
# =============================================================================

set -e  # Arrêt en cas d'erreur

# Configuration des couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables de configuration
INSTALL_DIR="/var/www/html/fidaous-pro"
DB_NAME="database_fidaous_pro"
DB_USER="fidaous_user"
DB_CHARSET="utf8mb4"
APACHE_USER="www-data"
PHP_VERSION="8.2"
MARIADB_VERSION="10.11"

# Configuration sécurisée
ADMIN_EMAIL="admin@fidaouspro.ma"
BACKUP_DIR="/backup/fidaous-pro"
LOG_FILE="/var/log/fidaous-pro-install.log"

# Fonction d'affichage avec couleurs
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a $LOG_FILE
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a $LOG_FILE
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a $LOG_FILE
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a $LOG_FILE
}

# Fonction de génération de mots de passe sécurisés
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Vérification des privilèges root
check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Ce script doit être exécuté avec les privilèges root (sudo)"
        exit 1
    fi
}

# Vérification de la version Debian
check_debian_version() {
    if ! grep -q "bookworm" /etc/os-release; then
        print_warning "Ce script est optimisé pour Debian 12 (Bookworm)"
        read -p "Continuer malgré tout ? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Mise à jour du système
update_system() {
    print_status "Mise à jour du système Debian 12..."
    apt update && apt upgrade -y
    apt install -y curl wget gpg software-properties-common apt-transport-https ca-certificates
    print_success "Système mis à jour avec succès"
}

# Installation d'Apache2
install_apache() {
    print_status "Installation et configuration d'Apache2..."
    
    apt install -y apache2
    
    # Activation des modules nécessaires
    a2enmod rewrite ssl headers expires deflate
    
    # Configuration de sécurité Apache
    cat > /etc/apache2/conf-available/security-fidaous.conf << 'EOF'
# Configuration de sécurité pour Fidaous Pro
ServerTokens Prod
ServerSignature Off
TraceEnable Off

# Headers de sécurité
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"

# Protection contre les attaques de timing
Header always set X-Permitted-Cross-Domain-Policies none
EOF
    
    a2enconf security-fidaous
    
    # Désactivation du site par défaut
    a2dissite 000-default
    
    systemctl enable apache2
    systemctl restart apache2
    
    print_success "Apache2 installé et configuré"
}

# Installation de PHP 8.2
install_php() {
    print_status "Installation de PHP ${PHP_VERSION} et des extensions..."
    
    apt install -y php${PHP_VERSION} php${PHP_VERSION}-fpm php${PHP_VERSION}-cli php${PHP_VERSION}-common \
        php${PHP_VERSION}-mysql php${PHP_VERSION}-xml php${PHP_VERSION}-xmlrpc \
        php${PHP_VERSION}-curl php${PHP_VERSION}-gd php${PHP_VERSION}-imagick \
        php${PHP_VERSION}-dev php${PHP_VERSION}-imap php${PHP_VERSION}-mbstring \
        php${PHP_VERSION}-opcache php${PHP_VERSION}-soap php${PHP_VERSION}-zip \
        php${PHP_VERSION}-intl php${PHP_VERSION}-bcmath php${PHP_VERSION}-json \
        libapache2-mod-php${PHP_VERSION}
    
    # Configuration PHP pour la production
    cat > /etc/php/${PHP_VERSION}/apache2/conf.d/99-fidaous-pro.ini << EOF
; Configuration PHP pour Fidaous Pro
memory_limit = 256M
max_execution_time = 300
max_input_vars = 3000
upload_max_filesize = 50M
post_max_size = 50M
max_file_uploads = 20
date.timezone = Africa/Casablanca
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
EOF
    
    systemctl restart apache2
    
    print_success "PHP ${PHP_VERSION} installé et configuré"
}

# Installation de MariaDB
install_mariadb() {
    print_status "Installation de MariaDB ${MARIADB_VERSION}..."
    
    apt install -y mariadb-server mariadb-client
    
    # Démarrage et activation du service
    systemctl enable mariadb
    systemctl start mariadb
    
    # Génération du mot de passe root MariaDB
    DB_ROOT_PASSWORD=$(generate_password)
    DB_PASSWORD=$(generate_password)
    
    print_status "Configuration sécurisée de MariaDB..."
    
    # Sécurisation de l'installation MariaDB
    mysql_secure_installation_script=$(cat << EOF
UPDATE mysql.user SET Password=PASSWORD('${DB_ROOT_PASSWORD}') WHERE User='root';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
)
    
    echo "${mysql_secure_installation_script}" | mysql
    
    # Configuration MariaDB pour Fidaous Pro
    cat > /etc/mysql/mariadb.conf.d/99-fidaous-pro.cnf << EOF
[mysqld]
# Configuration pour Fidaous Pro
innodb_buffer_pool_size = 512M
innodb_log_file_size = 128M
innodb_flush_log_at_trx_commit = 2
innodb_file_per_table = 1
query_cache_type = 1
query_cache_size = 64M
tmp_table_size = 64M
max_heap_table_size = 64M
max_connections = 200
thread_cache_size = 50
table_open_cache = 2000
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
init-connect = 'SET NAMES utf8mb4'

# Logs pour debugging
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
log_queries_not_using_indexes = 1

# Sécurité
bind-address = 127.0.0.1
local-infile = 0
EOF
    
    systemctl restart mariadb
    
    print_success "MariaDB installé et configuré"
    
    # Sauvegarde des mots de passe
    echo "DB_ROOT_PASSWORD=${DB_ROOT_PASSWORD}" >> /root/.fidaous-credentials
    echo "DB_PASSWORD=${DB_PASSWORD}" >> /root/.fidaous-credentials
    chmod 600 /root/.fidaous-credentials
}

# Installation de Composer
install_composer() {
    print_status "Installation de Composer..."
    
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    
    # Vérification de l'installation
    composer --version
    
    print_success "Composer installé avec succès"
}

# Installation de Node.js et npm
install_nodejs() {
    print_status "Installation de Node.js et npm..."
    
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt install -y nodejs
    
    # Vérification des versions
    node --version
    npm --version
    
    print_success "Node.js et npm installés avec succès"
}

# Création de la base de données et de l'utilisateur
setup_database() {
    print_status "Configuration de la base de données..."
    
    # Lecture des mots de passe
    source /root/.fidaous-credentials
    
    # Création de la base de données et de l'utilisateur
    mysql -u root -p${DB_ROOT_PASSWORD} << EOF
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET ${DB_CHARSET} COLLATE ${DB_CHARSET}_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
GRANT SELECT ON mysql.time_zone_name TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
EOF
    
    print_success "Base de données configurée"
}

# Déploiement de l'application Fidaous Pro
deploy_application() {
    print_status "Déploiement de l'application Fidaous Pro..."
    
    # Création de la structure de dossiers
    mkdir -p ${INSTALL_DIR}
    mkdir -p ${BACKUP_DIR}
    mkdir -p /var/log/fidaous-pro
    
    # Navigation vers le répertoire d'installation
    cd ${INSTALL_DIR}
    
    # Création de la structure de l'application
    mkdir -p {api,assets/{css,js,images,fonts},classes,config,cron,database,docs,includes,lang,logs,middleware,pages,storage/{temp,uploads/{documents,avatars,exports},backups/{database,files},cache/{views,data}},templates/{email,whatsapp,pdf,excel},tests/{unit,integration,feature},utils,webhooks,vendor}
    
    # Création du fichier index.html principal
    cat > index.html << 'EOF'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Fidaous Pro - Cabinet Comptable</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 0; padding: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .welcome-card { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); border-radius: 20px; padding: 3rem; text-align: center; max-width: 500px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1); }
        .logo { font-size: 3rem; color: #2c3e50; margin-bottom: 1rem; }
        h1 { color: #2c3e50; margin-bottom: 1rem; }
        .status { background: #d4edda; color: #155724; padding: 1rem; border-radius: 10px; margin: 1rem 0; border-left: 4px solid #28a745; }
        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 1rem 2rem; border: none; border-radius: 10px; text-decoration: none; display: inline-block; margin: 0.5rem; transition: transform 0.3s; }
        .btn:hover { transform: translateY(-2px); }
    </style>
</head>
<body>
    <div class="container">
        <div class="welcome-card">
            <div class="logo"><i class="fas fa-calculator"></i></div>
            <h1>Fidaous Pro</h1>
            <p>Cabinet Comptable - Maroc</p>
            <div class="status">
                <i class="fas fa-check-circle"></i>
                Installation réussie ! L'application est prête à être configurée.
            </div>
            <a href="pages/login.php" class="btn">
                <i class="fas fa-sign-in-alt"></i> Accéder à l'application
            </a>
            <a href="docs/README.md" class="btn">
                <i class="fas fa-book"></i> Documentation
            </a>
        </div>
    </div>
</body>
</html>
EOF
    
    # Configuration de base de données
    source /root/.fidaous-credentials
    cat > config/database.php << EOF
<?php
class Database {
    private \$host = 'localhost';
    private \$db_name = '${DB_NAME}';
    private \$username = '${DB_USER}';
    private \$password = '${DB_PASSWORD}';
    private \$charset = '${DB_CHARSET}';
    public \$pdo;

    public function getConnection() {
        \$this->pdo = null;
        try {
            \$dsn = "mysql:host=" . \$this->host . ";dbname=" . \$this->db_name . ";charset=" . \$this->charset;
            \$options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES ${DB_CHARSET}"
            ];
            \$this->pdo = new PDO(\$dsn, \$this->username, \$this->password, \$options);
        } catch(PDOException \$exception) {
            error_log("Erreur de connexion: " . \$exception->getMessage());
            throw \$exception;
        }
        return \$this->pdo;
    }
}
?>
EOF
    
    # Fichier .htaccess pour Apache
    cat > .htaccess << 'EOF'
# Configuration Apache pour Fidaous Pro
<IfModule mod_rewrite.c>
    RewriteEngine On
    
    # Redirection API
    RewriteRule ^api/(.*)$ api/endpoints.php [QSA,L]
    
    # Redirection Webhooks
    RewriteRule ^webhooks/(.*)$ webhooks/$1.php [QSA,L]
    
    # Protection des dossiers sensibles
    RewriteRule ^(config|classes|logs|storage|vendor)/ - [F,L]
</IfModule>

# Protection des fichiers sensibles
<FilesMatch "\.(env|sql|log|ini)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# Optimisation des performances
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType text/css "access plus 1 year"
    ExpiresByType application/javascript "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/jpg "access plus 1 year"
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/gif "access plus 1 year"
    ExpiresByType image/svg+xml "access plus 1 year"
</IfModule>

# Compression
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/xml
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/x-javascript
</IfModule>

# Sécurité
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
EOF
    
    print_success "Application déployée dans ${INSTALL_DIR}"
}

# Configuration du Virtual Host Apache
configure_virtualhost() {
    print_status "Configuration du Virtual Host Apache..."
    
    cat > /etc/apache2/sites-available/fidaous-pro.conf << EOF
<VirtualHost *:80>
    ServerName fidaous-pro.local
    DocumentRoot ${INSTALL_DIR}
    
    <Directory ${INSTALL_DIR}>
        AllowOverride All
        Require all granted
        Options -Indexes +FollowSymLinks
        DirectoryIndex index.html index.php
    </Directory>
    
    # Logs spécifiques
    ErrorLog \${APACHE_LOG_DIR}/fidaous-pro-error.log
    CustomLog \${APACHE_LOG_DIR}/fidaous-pro-access.log combined
    
    # Configuration PHP
    <FilesMatch \.php$>
        SetHandler application/x-httpd-php
    </FilesMatch>
</VirtualHost>

# Configuration HTTPS (à configurer avec un certificat SSL)
<VirtualHost *:443>
    ServerName fidaous-pro.local
    DocumentRoot ${INSTALL_DIR}
    
    # SSL Configuration (décommentez après avoir obtenu un certificat)
    # SSLEngine on
    # SSLCertificateFile /path/to/certificate.crt
    # SSLCertificateKeyFile /path/to/private.key
    
    <Directory ${INSTALL_DIR}>
        AllowOverride All
        Require all granted
        Options -Indexes +FollowSymLinks
        DirectoryIndex index.html index.php
    </Directory>
    
    # Headers de sécurité HTTPS
    <IfModule mod_headers.c>
        Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        Header always set X-Content-Type-Options nosniff
        Header always set X-Frame-Options DENY
        Header always set X-XSS-Protection "1; mode=block"
    </IfModule>
    
    ErrorLog \${APACHE_LOG_DIR}/fidaous-pro-ssl-error.log
    CustomLog \${APACHE_LOG_DIR}/fidaous-pro-ssl-access.log combined
</VirtualHost>
EOF
    
    # Activation du site
    a2ensite fidaous-pro.conf
    systemctl reload apache2
    
    print_success "Virtual Host configuré"
}

# Configuration des permissions
set_permissions() {
    print_status "Configuration des permissions de fichiers..."
    
    # Propriétaire et groupe
    chown -R ${APACHE_USER}:${APACHE_USER} ${INSTALL_DIR}
    
    # Permissions de base
    find ${INSTALL_DIR} -type d -exec chmod 755 {} \;
    find ${INSTALL_DIR} -type f -exec chmod 644 {} \;
    
    # Dossiers d'écriture
    chmod -R 775 ${INSTALL_DIR}/storage
    chmod -R 775 ${INSTALL_DIR}/logs
    chmod -R 775 ${BACKUP_DIR}
    
    # Protection des fichiers de configuration
    chmod 600 ${INSTALL_DIR}/config/database.php
    
    # Scripts exécutables
    find ${INSTALL_DIR}/cron -name "*.php" -exec chmod +x {} \;
    
    print_success "Permissions configurées"
}

# Installation des dépendances PHP avec Composer
install_php_dependencies() {
    print_status "Installation des dépendances PHP..."
    
    cd ${INSTALL_DIR}
    
    # Création du fichier composer.json
    cat > composer.json << 'EOF'
{
    "name": "fidaous-pro/cabinet-comptable",
    "description": "Application de gestion de cabinet comptable - Maroc",
    "type": "project",
    "require": {
        "php": ">=8.2",
        "phpmailer/phpmailer": "^6.8",
        "tecnickcom/tcpdf": "^6.6",
        "phpoffice/phpspreadsheet": "^1.29",
        "monolog/monolog": "^3.4"
    },
    "require-dev": {
        "phpunit/phpunit": "^10.0"
    },
    "autoload": {
        "psr-4": {
            "FidaousPro\\": "classes/"
        }
    },
    "config": {
        "optimize-autoloader": true,
        "preferred-install": "dist",
        "sort-packages": true
    }
}
EOF
    
    # Installation des dépendances
    composer install --no-dev --optimize-autoloader
    
    print_success "Dépendances PHP installées"
}

# Configuration des tâches cron
setup_cron_jobs() {
    print_status "Configuration des tâches automatisées..."
    
    # Création du script de tâches quotidiennes
    cat > ${INSTALL_DIR}/cron/daily_tasks.php << 'EOF'
#!/usr/bin/env php
<?php
/**
 * Tâches quotidiennes Fidaous Pro
 * Exécution : tous les jours à 06:00
 */

require_once __DIR__ . '/../config/database.php';

try {
    $database = new Database();
    $db = $database->getConnection();
    
    // Log du début d'exécution
    error_log("[" . date('Y-m-d H:i:s') . "] Début des tâches quotidiennes", 3, "/var/log/fidaous-pro/cron.log");
    
    // Nettoyage des fichiers temporaires
    $tempDir = __DIR__ . '/../storage/temp';
    $files = glob($tempDir . '/*');
    $yesterday = time() - (24 * 60 * 60);
    
    foreach ($files as $file) {
        if (is_file($file) && filemtime($file) < $yesterday) {
            unlink($file);
        }
    }
    
    // Sauvegarde quotidienne de la base de données
    $backupFile = "/backup/fidaous-pro/database/db_backup_" . date('Y-m-d') . ".sql";
    $command = "mysqldump -u fidaous_user -p database_fidaous_pro > $backupFile 2>/dev/null";
    exec($command);
    
    // Suppression des anciennes sauvegardes (plus de 30 jours)
    $oldBackups = glob("/backup/fidaous-pro/database/db_backup_*.sql");
    $thirtyDaysAgo = time() - (30 * 24 * 60 * 60);
    
    foreach ($oldBackups as $backup) {
        if (filemtime($backup) < $thirtyDaysAgo) {
            unlink($backup);
        }
    }
    
    error_log("[" . date('Y-m-d H:i:s') . "] Tâches quotidiennes terminées avec succès", 3, "/var/log/fidaous-pro/cron.log");
    
} catch (Exception $e) {
    error_log("[" . date('Y-m-d H:i:s') . "] Erreur dans les tâches quotidiennes: " . $e->getMessage(), 3, "/var/log/fidaous-pro/cron.log");
}
?>
EOF
    
    chmod +x ${INSTALL_DIR}/cron/daily_tasks.php
    
    # Ajout de la tâche cron
    (crontab -l 2>/dev/null; echo "0 6 * * * ${INSTALL_DIR}/cron/daily_tasks.php") | crontab -
    
    print_success "Tâches automatisées configurées"
}

# Configuration du firewall
configure_firewall() {
    print_status "Configuration du firewall (UFW)..."
    
    # Installation et configuration d'UFW si pas déjà installé
    apt install -y ufw
    
    # Configuration de base
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Ouverture des ports nécessaires
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Limitation des tentatives SSH
    ufw limit ssh
    
    # Activation du firewall
    ufw --force enable
    
    print_success "Firewall configuré"
}

# Fonction de nettoyage en cas d'erreur
cleanup_on_error() {
    print_error "Une erreur s'est produite. Nettoyage en cours..."
    
    # Arrêt des services si nécessaire
    systemctl stop apache2 2>/dev/null || true
    systemctl stop mariadb 2>/dev/null || true
    
    # Suppression des fichiers partiellement installés
    rm -rf ${INSTALL_DIR} 2>/dev/null || true
    
    print_error "Installation interrompue. Vérifiez les logs pour plus de détails."
    exit 1
}

# Affichage du résumé final
display_final_summary() {
    echo
    echo "=============================================="
    echo "   INSTALLATION FIDAOUS PRO TERMINÉE"
    echo "=============================================="
    echo
    print_success "Application installée dans : ${INSTALL_DIR}"
    print_success "Base de données : ${DB_NAME}"
    print_success "Utilisateur DB : ${DB_USER}"
    print_success "Logs : /var/log/fidaous-pro/"
    print_success "Sauvegardes : ${BACKUP_DIR}"
    echo
    echo "INFORMATIONS DE CONNEXION :"
    echo "============================"
    source /root/.fidaous-credentials 2>/dev/null || true
    echo "URL : http://$(hostname -I | awk '{print $1}')/fidaous-pro"
    echo "Ou : http://localhost/fidaous-pro"
    echo
    echo "Base de données MariaDB :"
    echo "- Root password : ${DB_ROOT_PASSWORD:-'Voir /root/.fidaous-credentials'}"
    echo "- User password : ${DB_PASSWORD:-'Voir /root/.fidaous-credentials'}"
    echo
    echo "PROCHAINES ÉTAPES :"
    echo "=================="
    echo "1. Configurez un nom de domaine ou utilisez l'IP"
    echo "2. Obtenez un certificat SSL pour HTTPS"
    echo "3. Configurez les intégrations (Nextcloud, WhatsApp)"
    echo "4. Importez la structure de base de données"
    echo "5. Créez le premier utilisateur administrateur"
    echo
    echo "DOCUMENTATION :"
    echo "==============="
    echo "- Guide complet : ${INSTALL_DIR}/docs/"
    echo "- Logs installation : ${LOG_FILE}"
    echo "- Support : admin@fidaouspro.ma"
    echo
    print_success "Installation terminée avec succès !"
}

# Fonction principale d'installation
main() {
    echo "=============================================="
    echo "   INSTALLATION FIDAOUS PRO - DEBIAN 12"
    echo "=============================================="
    echo
    
    # Configuration du gestionnaire d'erreurs
    trap cleanup_on_error ERR
    
    # Vérifications préliminaires
    check_root_privileges
    check_debian_version
    
    # Création du fichier de log
    touch $LOG_FILE
    chmod 644 $LOG_FILE
    
    print_status "Début de l'installation - $(date)"
    
    # Étapes d'installation
    update_system
    install_apache
    install_php
    install_mariadb
    install_composer
    install_nodejs
    setup_database
    deploy_application
    configure_virtualhost
    set_permissions
    install_php_dependencies
    setup_cron_jobs
    configure_firewall
    
    # Affichage du résumé
    display_final_summary
}

# Point d'entrée du script
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi