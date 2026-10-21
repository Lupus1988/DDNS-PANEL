from __future__ import annotations

import html
import json
import secrets
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template_string, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from lib.ddns_core import (
    APP_DIR,
    AUTH_FILE,
    IP_BLOCK_FILE,
    LOGIN_LOCK_SECONDS,
    LOGIN_MAX_ATTEMPTS,
    PANEL_PORT,
    RESET_PIN_LOCK_SECONDS,
    RESET_PIN_MAX_ATTEMPTS,
    SESSION_TIMEOUT_MINUTES,
    build_update_command,
    delete_entry_secret,
    entry_hostnames,
    ensure_runtime_layout,
    find_entry,
    get_entry_secret,
    get_primary_lan_ip,
    load_entries,
    load_json,
    load_or_create_secret_key,
    load_setup,
    load_status,
    now_iso,
    normalize_hostnames,
    remove_panel_runtime,
    run_panel_update,
    save_entries,
    save_json,
    save_setup,
    save_status,
    set_entry_secret,
    sync_local_access,
    sync_timer_unit,
    tail_audit_log,
    write_audit_log,
)


app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
REMEMBER_ME_DAYS = 3650
LANGUAGE_COOKIE = "ddns_panel_locale"
DEFAULT_LOCALE = "de-DE"
SUPPORTED_LOCALES = [
    "de-DE",
    "en-GB",
    "fr-FR",
    "es-ES",
    "it-IT",
    "nl-NL",
    "pl-PL",
    "pt-PT",
]
LOCALE_LABELS = {
    "de-DE": "Deutsch",
    "en-GB": "English",
    "fr-FR": "Français",
    "es-ES": "Español",
    "it-IT": "Italiano",
    "nl-NL": "Nederlands",
    "pl-PL": "Polski",
    "pt-PT": "Português",
}
LOCALE_SHORT_LABELS = {
    "de-DE": "DE",
    "en-GB": "EN",
    "fr-FR": "FR",
    "es-ES": "ES",
    "it-IT": "IT",
    "nl-NL": "NL",
    "pl-PL": "PL",
    "pt-PT": "PT",
}
LOCALE_FLAG_SVGS = {
    "de-DE": '<svg viewBox="0 0 18 12" class="flag-badge" aria-hidden="true"><rect width="18" height="4" y="0" fill="#111111"/><rect width="18" height="4" y="4" fill="#c62828"/><rect width="18" height="4" y="8" fill="#f2c94c"/></svg>',
    "en-GB": '<img class="flag-badge flag-image" src="https://flagemoji.net/img/flags/united-kingdom-flag.png" alt="">',
    "fr-FR": '<svg viewBox="0 0 18 12" class="flag-badge" aria-hidden="true"><rect width="6" height="12" x="0" fill="#1f5fbf"/><rect width="6" height="12" x="6" fill="#f7f7f7"/><rect width="6" height="12" x="12" fill="#d63b3b"/></svg>',
    "es-ES": '<svg viewBox="0 0 18 12" class="flag-badge" aria-hidden="true"><rect width="18" height="12" fill="#aa151b"/><rect width="18" height="6" y="3" fill="#f1bf00"/><rect width="2.2" height="3" x="4.2" y="4.5" rx=".3" fill="#aa151b"/><rect width="1.1" height="2.1" x="4.75" y="4.95" fill="#f1bf00"/></svg>',
    "it-IT": '<svg viewBox="0 0 18 12" class="flag-badge" aria-hidden="true"><rect width="6" height="12" x="0" fill="#1f8f4e"/><rect width="6" height="12" x="6" fill="#f7f7f7"/><rect width="6" height="12" x="12" fill="#d63b3b"/></svg>',
    "nl-NL": '<svg viewBox="0 0 18 12" class="flag-badge" aria-hidden="true"><rect width="18" height="4" y="0" fill="#ae1c28"/><rect width="18" height="4" y="4" fill="#f7f7f7"/><rect width="18" height="4" y="8" fill="#21468b"/></svg>',
    "pl-PL": '<svg viewBox="0 0 18 12" class="flag-badge" aria-hidden="true"><rect width="18" height="6" y="0" fill="#f7f7f7"/><rect width="18" height="6" y="6" fill="#dc143c"/></svg>',
    "pt-PT": '<svg viewBox="0 0 18 12" class="flag-badge" aria-hidden="true"><rect width="18" height="12" fill="#da291c"/><rect width="7.2" height="12" x="0" fill="#046a38"/><circle cx="7.2" cy="6" r="2" fill="none" stroke="#f2c94c" stroke-width="1"/><circle cx="7.2" cy="6" r=".8" fill="#f7f7f7"/></svg>',
}
TRANSLATIONS = {
    "dashboard": {
        "de-DE": "Dashboard",
        "en-GB": "Dashboard",
        "fr-FR": "Tableau de bord",
        "es-ES": "Panel",
        "it-IT": "Dashboard",
        "nl-NL": "Dashboard",
        "pl-PL": "Panel",
        "pt-PT": "Painel",
    },
    "services": {
        "de-DE": "Dienste",
        "en-GB": "Services",
        "fr-FR": "Services",
        "es-ES": "Servicios",
        "it-IT": "Servizi",
        "nl-NL": "Diensten",
        "pl-PL": "Usługi",
        "pt-PT": "Serviços",
    },
    "setup": {
        "de-DE": "Setup",
        "en-GB": "Setup",
        "fr-FR": "Configuration",
        "es-ES": "Configuración",
        "it-IT": "Configurazione",
        "nl-NL": "Instellingen",
        "pl-PL": "Konfiguracja",
        "pt-PT": "Configuração",
    },
    "logout": {
        "de-DE": "Logout",
        "en-GB": "Log out",
        "fr-FR": "Déconnexion",
        "es-ES": "Cerrar sesión",
        "it-IT": "Esci",
        "nl-NL": "Uitloggen",
        "pl-PL": "Wyloguj",
        "pt-PT": "Terminar sessão",
    },
    "language": {
        "de-DE": "Sprache",
        "en-GB": "Language",
        "fr-FR": "Langue",
        "es-ES": "Idioma",
        "it-IT": "Lingua",
        "nl-NL": "Taal",
        "pl-PL": "Język",
        "pt-PT": "Idioma",
    },
    "panel_locked": {
        "de-DE": "Panel gesperrt",
        "en-GB": "Panel locked",
        "fr-FR": "Panneau verrouillé",
        "es-ES": "Panel bloqueado",
        "it-IT": "Pannello bloccato",
        "nl-NL": "Paneel vergrendeld",
        "pl-PL": "Panel zablokowany",
        "pt-PT": "Painel bloqueado",
    },
    "initial_setup_title": {
        "de-DE": "DDNS Panel Ersteinrichtung",
        "en-GB": "DDNS Panel Initial Setup",
        "fr-FR": "Configuration initiale du panneau DDNS",
        "es-ES": "Configuración inicial del panel DDNS",
        "it-IT": "Configurazione iniziale del pannello DDNS",
        "nl-NL": "Eerste configuratie van het DDNS-paneel",
        "pl-PL": "Początkowa konfiguracja panelu DDNS",
        "pt-PT": "Configuração inicial do painel DDNS",
    },
    "no_access_configured": {
        "de-DE": "Es ist noch kein Panel-Zugang eingerichtet.",
        "en-GB": "No panel access has been configured yet.",
        "fr-FR": "Aucun accès au panneau n'a encore été configuré.",
        "es-ES": "Todavía no se ha configurado ningún acceso al panel.",
        "it-IT": "Non è ancora stato configurato alcun accesso al pannello.",
        "nl-NL": "Er is nog geen toegang tot het paneel ingesteld.",
        "pl-PL": "Nie skonfigurowano jeszcze dostępu do panelu.",
        "pt-PT": "Ainda não foi configurado qualquer acesso ao painel.",
    },
    "username": {
        "de-DE": "Benutzername",
        "en-GB": "Username",
        "fr-FR": "Nom d'utilisateur",
        "es-ES": "Nombre de usuario",
        "it-IT": "Nome utente",
        "nl-NL": "Gebruikersnaam",
        "pl-PL": "Nazwa użytkownika",
        "pt-PT": "Nome de utilizador",
    },
    "password": {
        "de-DE": "Passwort",
        "en-GB": "Password",
        "fr-FR": "Mot de passe",
        "es-ES": "Contraseña",
        "it-IT": "Password",
        "nl-NL": "Wachtwoord",
        "pl-PL": "Hasło",
        "pt-PT": "Palavra-passe",
    },
    "repeat_password": {
        "de-DE": "Passwort wiederholen",
        "en-GB": "Repeat password",
        "fr-FR": "Répéter le mot de passe",
        "es-ES": "Repetir contraseña",
        "it-IT": "Ripeti password",
        "nl-NL": "Wachtwoord herhalen",
        "pl-PL": "Powtórz hasło",
        "pt-PT": "Repetir palavra-passe",
    },
    "reset_pin": {
        "de-DE": "Reset-PIN",
        "en-GB": "Reset PIN",
        "fr-FR": "PIN de réinitialisation",
        "es-ES": "PIN de restablecimiento",
        "it-IT": "PIN di reset",
        "nl-NL": "Reset-pincode",
        "pl-PL": "PIN resetu",
        "pt-PT": "PIN de reposição",
    },
    "complete_setup": {
        "de-DE": "Einrichtung abschließen",
        "en-GB": "Complete setup",
        "fr-FR": "Terminer la configuration",
        "es-ES": "Completar configuración",
        "it-IT": "Completa configurazione",
        "nl-NL": "Configuratie afronden",
        "pl-PL": "Zakończ konfigurację",
        "pt-PT": "Concluir configuração",
    },
    "fill_all_fields": {
        "de-DE": "Bitte alle Felder ausfüllen.",
        "en-GB": "Please fill in all fields.",
        "fr-FR": "Veuillez remplir tous les champs.",
        "es-ES": "Rellena todos los campos.",
        "it-IT": "Compila tutti i campi.",
        "nl-NL": "Vul alle velden in.",
        "pl-PL": "Wypełnij wszystkie pola.",
        "pt-PT": "Preencha todos os campos.",
    },
    "passwords_do_not_match": {
        "de-DE": "Die Passwörter stimmen nicht überein.",
        "en-GB": "The passwords do not match.",
        "fr-FR": "Les mots de passe ne correspondent pas.",
        "es-ES": "Las contraseñas no coinciden.",
        "it-IT": "Le password non coincidono.",
        "nl-NL": "De wachtwoorden komen niet overeen.",
        "pl-PL": "Hasła nie są zgodne.",
        "pt-PT": "As palavras-passe não coincidem.",
    },
    "password_min_length": {
        "de-DE": "Das Passwort muss mindestens 8 Zeichen lang sein.",
        "en-GB": "The password must be at least 8 characters long.",
        "fr-FR": "Le mot de passe doit contenir au moins 8 caractères.",
        "es-ES": "La contraseña debe tener al menos 8 caracteres.",
        "it-IT": "La password deve contenere almeno 8 caratteri.",
        "nl-NL": "Het wachtwoord moet minimaal 8 tekens lang zijn.",
        "pl-PL": "Hasło musi mieć co najmniej 8 znaków.",
        "pt-PT": "A palavra-passe deve ter pelo menos 8 caracteres.",
    },
    "pin_min_length": {
        "de-DE": "Die Reset-PIN muss mindestens 4 Zeichen lang sein.",
        "en-GB": "The reset PIN must be at least 4 characters long.",
        "fr-FR": "Le PIN de réinitialisation doit contenir au moins 4 caractères.",
        "es-ES": "El PIN de restablecimiento debe tener al menos 4 caracteres.",
        "it-IT": "Il PIN di reset deve contenere almeno 4 caratteri.",
        "nl-NL": "De reset-pincode moet minimaal 4 tekens lang zijn.",
        "pl-PL": "PIN resetu musi mieć co najmniej 4 znaki.",
        "pt-PT": "O PIN de reposição deve ter pelo menos 4 caracteres.",
    },
    "login": {
        "de-DE": "Login",
        "en-GB": "Login",
        "fr-FR": "Connexion",
        "es-ES": "Acceso",
        "it-IT": "Accesso",
        "nl-NL": "Inloggen",
        "pl-PL": "Logowanie",
        "pt-PT": "Iniciar sessão",
    },
    "remember_me": {
        "de-DE": "Angemeldet bleiben",
        "en-GB": "Keep me signed in",
        "fr-FR": "Rester connecté",
        "es-ES": "Mantener sesión iniciada",
        "it-IT": "Resta connesso",
        "nl-NL": "Aangemeld blijven",
        "pl-PL": "Pozostań zalogowany",
        "pt-PT": "Manter sessão iniciada",
    },
    "sign_in": {
        "de-DE": "Anmelden",
        "en-GB": "Sign in",
        "fr-FR": "Se connecter",
        "es-ES": "Iniciar sesión",
        "it-IT": "Accedi",
        "nl-NL": "Inloggen",
        "pl-PL": "Zaloguj",
        "pt-PT": "Entrar",
    },
    "reset_access": {
        "de-DE": "Zugang zurücksetzen",
        "en-GB": "Reset access",
        "fr-FR": "Réinitialiser l'accès",
        "es-ES": "Restablecer acceso",
        "it-IT": "Reimposta accesso",
        "nl-NL": "Toegang resetten",
        "pl-PL": "Zresetuj dostęp",
        "pt-PT": "Repor acesso",
    },
    "login_locked": {
        "de-DE": "Login ist aktuell gesperrt. Erneut versuchen in ca. {minutes} Minute(n).",
        "en-GB": "Login is currently locked. Try again in about {minutes} minute(s).",
        "fr-FR": "La connexion est actuellement verrouillée. Réessayez dans environ {minutes} minute(s).",
        "es-ES": "El acceso está bloqueado. Vuelve a intentarlo en aproximadamente {minutes} minuto(s).",
        "it-IT": "Accesso attualmente bloccato. Riprova tra circa {minutes} minuto/i.",
        "nl-NL": "Inloggen is momenteel geblokkeerd. Probeer het over ongeveer {minutes} minuut/minuten opnieuw.",
        "pl-PL": "Logowanie jest obecnie zablokowane. Spróbuj ponownie za około {minutes} min.",
        "pt-PT": "O início de sessão está bloqueado. Tente novamente dentro de cerca de {minutes} minuto(s).",
    },
    "enter_username_password": {
        "de-DE": "Bitte Benutzername und Passwort eingeben.",
        "en-GB": "Please enter username and password.",
        "fr-FR": "Veuillez saisir le nom d'utilisateur et le mot de passe.",
        "es-ES": "Introduce el nombre de usuario y la contraseña.",
        "it-IT": "Inserisci nome utente e password.",
        "nl-NL": "Voer gebruikersnaam en wachtwoord in.",
        "pl-PL": "Wpisz nazwę użytkownika i hasło.",
        "pt-PT": "Introduza o nome de utilizador e a palavra-passe.",
    },
    "invalid_login_attempts_left": {
        "de-DE": "Ungültiger Benutzername oder Passwort. Verbleibende Versuche: {remaining}",
        "en-GB": "Invalid username or password. Remaining attempts: {remaining}",
        "fr-FR": "Nom d'utilisateur ou mot de passe invalide. Tentatives restantes : {remaining}",
        "es-ES": "Usuario o contraseña no válidos. Intentos restantes: {remaining}",
        "it-IT": "Nome utente o password non validi. Tentativi rimasti: {remaining}",
        "nl-NL": "Ongeldige gebruikersnaam of wachtwoord. Resterende pogingen: {remaining}",
        "pl-PL": "Nieprawidłowa nazwa użytkownika lub hasło. Pozostałe próby: {remaining}",
        "pt-PT": "Nome de utilizador ou palavra-passe inválidos. Tentativas restantes: {remaining}",
    },
    "new_username": {
        "de-DE": "Neuer Benutzername",
        "en-GB": "New username",
        "fr-FR": "Nouveau nom d'utilisateur",
        "es-ES": "Nuevo nombre de usuario",
        "it-IT": "Nuovo nome utente",
        "nl-NL": "Nieuwe gebruikersnaam",
        "pl-PL": "Nowa nazwa użytkownika",
        "pt-PT": "Novo nome de utilizador",
    },
    "new_password": {
        "de-DE": "Neues Passwort",
        "en-GB": "New password",
        "fr-FR": "Nouveau mot de passe",
        "es-ES": "Nueva contraseña",
        "it-IT": "Nuova password",
        "nl-NL": "Nieuw wachtwoord",
        "pl-PL": "Nowe hasło",
        "pt-PT": "Nova palavra-passe",
    },
    "repeat_new_password": {
        "de-DE": "Neues Passwort wiederholen",
        "en-GB": "Repeat new password",
        "fr-FR": "Répéter le nouveau mot de passe",
        "es-ES": "Repetir nueva contraseña",
        "it-IT": "Ripeti nuova password",
        "nl-NL": "Nieuw wachtwoord herhalen",
        "pl-PL": "Powtórz nowe hasło",
        "pt-PT": "Repetir nova palavra-passe",
    },
    "back": {
        "de-DE": "Zurück",
        "en-GB": "Back",
        "fr-FR": "Retour",
        "es-ES": "Volver",
        "it-IT": "Indietro",
        "nl-NL": "Terug",
        "pl-PL": "Wstecz",
        "pt-PT": "Voltar",
    },
    "reset_locked": {
        "de-DE": "Reset-Zugang ist aktuell gesperrt. Erneut versuchen in ca. {minutes} Minute(n).",
        "en-GB": "Reset access is currently locked. Try again in about {minutes} minute(s).",
        "fr-FR": "L'accès de réinitialisation est verrouillé. Réessayez dans environ {minutes} minute(s).",
        "es-ES": "El acceso de restablecimiento está bloqueado. Vuelve a intentarlo en aproximadamente {minutes} minuto(s).",
        "it-IT": "L'accesso di ripristino è bloccato. Riprova tra circa {minutes} minuto/i.",
        "nl-NL": "Resettoegang is momenteel geblokkeerd. Probeer het over ongeveer {minutes} minuut/minuten opnieuw.",
        "pl-PL": "Dostęp resetowania jest zablokowany. Spróbuj ponownie za około {minutes} min.",
        "pt-PT": "O acesso de reposição está bloqueado. Tente novamente dentro de cerca de {minutes} minuto(s).",
    },
    "invalid_reset_pin_attempts_left": {
        "de-DE": "Ungültige Reset-PIN. Verbleibende Versuche: {remaining}",
        "en-GB": "Invalid reset PIN. Remaining attempts: {remaining}",
        "fr-FR": "PIN de réinitialisation invalide. Tentatives restantes : {remaining}",
        "es-ES": "PIN de restablecimiento no válido. Intentos restantes: {remaining}",
        "it-IT": "PIN di reset non valido. Tentativi rimasti: {remaining}",
        "nl-NL": "Ongeldige reset-pincode. Resterende pogingen: {remaining}",
        "pl-PL": "Nieprawidłowy PIN resetu. Pozostałe próby: {remaining}",
        "pt-PT": "PIN de reposição inválido. Tentativas restantes: {remaining}",
    },
    "factory_reset": {
        "de-DE": "Werksreset",
        "en-GB": "Factory reset",
        "fr-FR": "Réinitialisation d'usine",
        "es-ES": "Restablecimiento de fábrica",
        "it-IT": "Ripristino di fabbrica",
        "nl-NL": "Fabrieksreset",
        "pl-PL": "Reset fabryczny",
        "pt-PT": "Reposição de fábrica",
    },
    "factory_reset_warning": {
        "de-DE": "Löscht nur Panel-Konfiguration, Secrets und Status. Deine sonstigen Server-Dienste bleiben unberührt.",
        "en-GB": "Deletes only panel configuration, secrets and status. Your other server services remain untouched.",
        "fr-FR": "Supprime uniquement la configuration, les secrets et l'état du panneau. Les autres services du serveur restent intacts.",
        "es-ES": "Solo elimina la configuración, los secretos y el estado del panel. Los demás servicios del servidor no se modifican.",
        "it-IT": "Elimina solo configurazione, segreti e stato del pannello. Gli altri servizi del server restano invariati.",
        "nl-NL": "Verwijdert alleen paneelconfiguratie, secrets en status. Je andere serverdiensten blijven ongemoeid.",
        "pl-PL": "Usuwa tylko konfigurację panelu, sekrety i stan. Pozostałe usługi serwera pozostają bez zmian.",
        "pt-PT": "Elimina apenas a configuração, os segredos e o estado do painel. Os restantes serviços do servidor não são afetados.",
    },
    "open_factory_reset": {
        "de-DE": "Werksreset öffnen",
        "en-GB": "Open factory reset",
        "fr-FR": "Ouvrir la réinitialisation d'usine",
        "es-ES": "Abrir restablecimiento de fábrica",
        "it-IT": "Apri ripristino di fabbrica",
        "nl-NL": "Fabrieksreset openen",
        "pl-PL": "Otwórz reset fabryczny",
        "pt-PT": "Abrir reposição de fábrica",
    },
    "confirm_text": {
        "de-DE": "Bestätigungstext",
        "en-GB": "Confirmation text",
        "fr-FR": "Texte de confirmation",
        "es-ES": "Texto de confirmación",
        "it-IT": "Testo di conferma",
        "nl-NL": "Bevestigingstekst",
        "pl-PL": "Tekst potwierdzenia",
        "pt-PT": "Texto de confirmação",
    },
    "factory_reset_confirm_exact": {
        "de-DE": 'Bitte zur Bestätigung exakt "WERKSRESET" eingeben.',
        "en-GB": 'Please enter exactly "WERKSRESET" to confirm.',
        "fr-FR": 'Veuillez saisir exactement "WERKSRESET" pour confirmer.',
        "es-ES": 'Escribe exactamente "WERKSRESET" para confirmar.',
        "it-IT": 'Inserisci esattamente "WERKSRESET" per confermare.',
        "nl-NL": 'Voer precies "WERKSRESET" in ter bevestiging.',
        "pl-PL": 'Aby potwierdzić, wpisz dokładnie "WERKSRESET".',
        "pt-PT": 'Introduza exatamente "WERKSRESET" para confirmar.',
    },
    "items_deleted": {
        "de-DE": "Es werden gelöscht:",
        "en-GB": "The following will be deleted:",
        "fr-FR": "Les éléments suivants seront supprimés :",
        "es-ES": "Se eliminará lo siguiente:",
        "it-IT": "Verranno eliminati:",
        "nl-NL": "Het volgende wordt verwijderd:",
        "pl-PL": "Usunięte zostaną:",
        "pt-PT": "Serão eliminados:",
    },
    "panel_access": {
        "de-DE": "Panel-Zugang",
        "en-GB": "Panel access",
        "fr-FR": "Accès au panneau",
        "es-ES": "Acceso al panel",
        "it-IT": "Accesso al pannello",
        "nl-NL": "Paneeltoegang",
        "pl-PL": "Dostęp do panelu",
        "pt-PT": "Acesso ao painel",
    },
    "ddns_entries": {
        "de-DE": "DDNS-Einträge",
        "en-GB": "DDNS entries",
        "fr-FR": "Entrées DDNS",
        "es-ES": "Entradas DDNS",
        "it-IT": "Voci DDNS",
        "nl-NL": "DDNS-vermeldingen",
        "pl-PL": "Wpisy DDNS",
        "pt-PT": "Entradas DDNS",
    },
    "provider_secrets": {
        "de-DE": "Provider-Secrets",
        "en-GB": "Provider secrets",
        "fr-FR": "Secrets des fournisseurs",
        "es-ES": "Secretos del proveedor",
        "it-IT": "Segreti del provider",
        "nl-NL": "Provider-secrets",
        "pl-PL": "Sekrety dostawcy",
        "pt-PT": "Segredos do fornecedor",
    },
    "local_status_logs": {
        "de-DE": "lokaler Status und Logs",
        "en-GB": "local status and logs",
        "fr-FR": "état local et journaux",
        "es-ES": "estado y registros locales",
        "it-IT": "stato locale e log",
        "nl-NL": "lokale status en logs",
        "pl-PL": "lokalny stan i logi",
        "pt-PT": "estado local e registos",
    },
    "run_factory_reset": {
        "de-DE": "Werksreset endgültig ausführen",
        "en-GB": "Run factory reset permanently",
        "fr-FR": "Exécuter définitivement la réinitialisation d'usine",
        "es-ES": "Ejecutar restablecimiento de fábrica definitivamente",
        "it-IT": "Esegui definitivamente il ripristino di fabbrica",
        "nl-NL": "Fabrieksreset definitief uitvoeren",
        "pl-PL": "Wykonaj reset fabryczny na stałe",
        "pt-PT": "Executar reposição de fábrica em definitivo",
    },
    "status": {
        "de-DE": "Status",
        "en-GB": "Status",
        "fr-FR": "Statut",
        "es-ES": "Estado",
        "it-IT": "Stato",
        "nl-NL": "Status",
        "pl-PL": "Stan",
        "pt-PT": "Estado",
    },
    "current_public_ipv4": {
        "de-DE": "Aktuelle öffentliche IPv4",
        "en-GB": "Current public IPv4",
        "fr-FR": "IPv4 publique actuelle",
        "es-ES": "IPv4 pública actual",
        "it-IT": "IPv4 pubblica attuale",
        "nl-NL": "Huidige publieke IPv4",
        "pl-PL": "Aktualny publiczny IPv4",
        "pt-PT": "IPv4 pública atual",
    },
    "current_public_ipv6": {
        "de-DE": "Aktuelle öffentliche IPv6",
        "en-GB": "Current public IPv6",
        "fr-FR": "IPv6 publique actuelle",
        "es-ES": "IPv6 pública actual",
        "it-IT": "IPv6 pubblica attuale",
        "nl-NL": "Huidige publieke IPv6",
        "pl-PL": "Aktualny publiczny IPv6",
        "pt-PT": "IPv6 pública atual",
    },
    "last_check": {
        "de-DE": "Letzte Prüfung",
        "en-GB": "Last check",
        "fr-FR": "Dernière vérification",
        "es-ES": "Última comprobación",
        "it-IT": "Ultimo controllo",
        "nl-NL": "Laatste controle",
        "pl-PL": "Ostatnie sprawdzenie",
        "pt-PT": "Última verificação",
    },
    "last_change": {
        "de-DE": "Letzte Änderung",
        "en-GB": "Last change",
        "fr-FR": "Dernier changement",
        "es-ES": "Último cambio",
        "it-IT": "Ultima modifica",
        "nl-NL": "Laatste wijziging",
        "pl-PL": "Ostatnia zmiana",
        "pt-PT": "Última alteração",
    },
    "summary": {
        "de-DE": "Zusammenfassung",
        "en-GB": "Summary",
        "fr-FR": "Résumé",
        "es-ES": "Resumen",
        "it-IT": "Riepilogo",
        "nl-NL": "Samenvatting",
        "pl-PL": "Podsumowanie",
        "pt-PT": "Resumo",
    },
    "update_interval": {
        "de-DE": "Update-Intervall",
        "en-GB": "Update interval",
        "fr-FR": "Intervalle de mise à jour",
        "es-ES": "Intervalo de actualización",
        "it-IT": "Intervallo di aggiornamento",
        "nl-NL": "Update-interval",
        "pl-PL": "Interwał aktualizacji",
        "pt-PT": "Intervalo de atualização",
    },
    "every_minutes": {
        "de-DE": "alle {minutes} Minute(n)",
        "en-GB": "every {minutes} minute(s)",
        "fr-FR": "toutes les {minutes} minute(s)",
        "es-ES": "cada {minutes} minuto(s)",
        "it-IT": "ogni {minutes} minuto/i",
        "nl-NL": "elke {minutes} minuut/minuten",
        "pl-PL": "co {minutes} min",
        "pt-PT": "a cada {minutes} minuto(s)",
    },
    "panel_process": {
        "de-DE": "Panel-Prozess",
        "en-GB": "Panel process",
        "fr-FR": "Processus du panneau",
        "es-ES": "Proceso del panel",
        "it-IT": "Processo del pannello",
        "nl-NL": "Paneelproces",
        "pl-PL": "Proces panelu",
        "pt-PT": "Processo do painel",
    },
    "ddns_services": {
        "de-DE": "DDNS-Dienste",
        "en-GB": "DDNS services",
        "fr-FR": "Services DDNS",
        "es-ES": "Servicios DDNS",
        "it-IT": "Servizi DDNS",
        "nl-NL": "DDNS-diensten",
        "pl-PL": "Usługi DDNS",
        "pt-PT": "Serviços DDNS",
    },
    "enabled": {
        "de-DE": "Aktiv",
        "en-GB": "Enabled",
        "fr-FR": "Actif",
        "es-ES": "Activo",
        "it-IT": "Attivo",
        "nl-NL": "Actief",
        "pl-PL": "Aktywne",
        "pt-PT": "Ativo",
    },
    "name": {
        "de-DE": "Name",
        "en-GB": "Name",
        "fr-FR": "Nom",
        "es-ES": "Nombre",
        "it-IT": "Nome",
        "nl-NL": "Naam",
        "pl-PL": "Nazwa",
        "pt-PT": "Nome",
    },
    "provider": {
        "de-DE": "Provider",
        "en-GB": "Provider",
        "fr-FR": "Fournisseur",
        "es-ES": "Proveedor",
        "it-IT": "Provider",
        "nl-NL": "Provider",
        "pl-PL": "Dostawca",
        "pt-PT": "Fornecedor",
    },
    "ip_mode": {
        "de-DE": "IP-Modus",
        "en-GB": "IP mode",
        "fr-FR": "Mode IP",
        "es-ES": "Modo IP",
        "it-IT": "Modalità IP",
        "nl-NL": "IP-modus",
        "pl-PL": "Tryb IP",
        "pt-PT": "Modo IP",
    },
    "hostname_domain": {
        "de-DE": "Hostname / Domain",
        "en-GB": "Hostname / domain",
        "fr-FR": "Nom d'hôte / domaine",
        "es-ES": "Nombre de host / dominio",
        "it-IT": "Hostname / dominio",
        "nl-NL": "Hostnaam / domein",
        "pl-PL": "Nazwa hosta / domena",
        "pt-PT": "Nome do host / domínio",
    },
    "service_status": {
        "de-DE": "Status",
        "en-GB": "Status",
        "fr-FR": "Statut",
        "es-ES": "Estado",
        "it-IT": "Stato",
        "nl-NL": "Status",
        "pl-PL": "Stan",
        "pt-PT": "Estado",
    },
    "last_ipv4": {
        "de-DE": "Letzte IPv4",
        "en-GB": "Last IPv4",
        "fr-FR": "Dernière IPv4",
        "es-ES": "Última IPv4",
        "it-IT": "Ultima IPv4",
        "nl-NL": "Laatste IPv4",
        "pl-PL": "Ostatni IPv4",
        "pt-PT": "Última IPv4",
    },
    "last_ipv6": {
        "de-DE": "Letzte IPv6",
        "en-GB": "Last IPv6",
        "fr-FR": "Dernière IPv6",
        "es-ES": "Última IPv6",
        "it-IT": "Ultima IPv6",
        "nl-NL": "Laatste IPv6",
        "pl-PL": "Ostatni IPv6",
        "pt-PT": "Última IPv6",
    },
    "last_update": {
        "de-DE": "Letztes Update",
        "en-GB": "Last update",
        "fr-FR": "Dernière mise à jour",
        "es-ES": "Última actualización",
        "it-IT": "Ultimo aggiornamento",
        "nl-NL": "Laatste update",
        "pl-PL": "Ostatnia aktualizacja",
        "pt-PT": "Última atualização",
    },
    "actions": {
        "de-DE": "Aktionen",
        "en-GB": "Actions",
        "fr-FR": "Actions",
        "es-ES": "Acciones",
        "it-IT": "Azioni",
        "nl-NL": "Acties",
        "pl-PL": "Akcje",
        "pt-PT": "Ações",
    },
    "edit": {
        "de-DE": "Bearbeiten",
        "en-GB": "Edit",
        "fr-FR": "Modifier",
        "es-ES": "Editar",
        "it-IT": "Modifica",
        "nl-NL": "Bewerken",
        "pl-PL": "Edytuj",
        "pt-PT": "Editar",
    },
    "test": {
        "de-DE": "Test",
        "en-GB": "Test",
        "fr-FR": "Tester",
        "es-ES": "Probar",
        "it-IT": "Test",
        "nl-NL": "Test",
        "pl-PL": "Test",
        "pt-PT": "Testar",
    },
    "waiting": {
        "de-DE": "Wartet",
        "en-GB": "Waiting",
        "fr-FR": "En attente",
        "es-ES": "En espera",
        "it-IT": "In attesa",
        "nl-NL": "Wacht",
        "pl-PL": "Oczekiwanie",
        "pt-PT": "Em espera",
    },
    "error_short": {
        "de-DE": "Fehler",
        "en-GB": "Error",
        "fr-FR": "Erreur",
        "es-ES": "Error",
        "it-IT": "Errore",
        "nl-NL": "Fout",
        "pl-PL": "Błąd",
        "pt-PT": "Erro",
    },
    "download_logs": {
        "de-DE": "Download Logs",
        "en-GB": "Download logs",
        "fr-FR": "Télécharger les journaux",
        "es-ES": "Descargar registros",
        "it-IT": "Scarica log",
        "nl-NL": "Logs downloaden",
        "pl-PL": "Pobierz logi",
        "pt-PT": "Descarregar registos",
    },
    "services_manage": {
        "de-DE": "Provider-Einträge und Zugangsdaten verwalten.",
        "en-GB": "Manage provider entries and credentials.",
        "fr-FR": "Gérer les entrées fournisseur et les identifiants.",
        "es-ES": "Gestiona las entradas del proveedor y las credenciales.",
        "it-IT": "Gestisci voci del provider e credenziali.",
        "nl-NL": "Beheer provideritems en inloggegevens.",
        "pl-PL": "Zarządzaj wpisami dostawców i danymi logowania.",
        "pt-PT": "Gerir entradas do fornecedor e credenciais.",
    },
    "run_now": {
        "de-DE": "Jetzt prüfen",
        "en-GB": "Run now",
        "fr-FR": "Lancer maintenant",
        "es-ES": "Comprobar ahora",
        "it-IT": "Esegui ora",
        "nl-NL": "Nu controleren",
        "pl-PL": "Sprawdź teraz",
        "pt-PT": "Executar agora",
    },
    "add_service": {
        "de-DE": "+Dienst",
        "en-GB": "+Service",
        "fr-FR": "+Service",
        "es-ES": "+Servicio",
        "it-IT": "+Servizio",
        "nl-NL": "+Dienst",
        "pl-PL": "+Usługa",
        "pt-PT": "+Serviço",
    },
    "last_result": {
        "de-DE": "Letztes Ergebnis",
        "en-GB": "Last result",
        "fr-FR": "Dernier résultat",
        "es-ES": "Último resultado",
        "it-IT": "Ultimo risultato",
        "nl-NL": "Laatste resultaat",
        "pl-PL": "Ostatni wynik",
        "pt-PT": "Último resultado",
    },
    "last_error": {
        "de-DE": "Letzter Fehler",
        "en-GB": "Last error",
        "fr-FR": "Dernière erreur",
        "es-ES": "Último error",
        "it-IT": "Ultimo errore",
        "nl-NL": "Laatste fout",
        "pl-PL": "Ostatni błąd",
        "pt-PT": "Último erro",
    },
    "delete": {
        "de-DE": "Löschen",
        "en-GB": "Delete",
        "fr-FR": "Supprimer",
        "es-ES": "Eliminar",
        "it-IT": "Elimina",
        "nl-NL": "Verwijderen",
        "pl-PL": "Usuń",
        "pt-PT": "Eliminar",
    },
    "confirm_delete": {
        "de-DE": "Eintrag wirklich löschen?",
        "en-GB": "Really delete this entry?",
        "fr-FR": "Supprimer vraiment cette entrée ?",
        "es-ES": "¿Eliminar realmente esta entrada?",
        "it-IT": "Eliminare davvero questa voce?",
        "nl-NL": "Deze vermelding echt verwijderen?",
        "pl-PL": "Na pewno usunąć ten wpis?",
        "pt-PT": "Eliminar mesmo esta entrada?",
    },
    "no_services_configured": {
        "de-DE": "Noch keine DDNS-Dienste eingerichtet.",
        "en-GB": "No DDNS services have been configured yet.",
        "fr-FR": "Aucun service DDNS n'a encore été configuré.",
        "es-ES": "Todavía no se ha configurado ningún servicio DDNS.",
        "it-IT": "Non è ancora stato configurato alcun servizio DDNS.",
        "nl-NL": "Er zijn nog geen DDNS-diensten ingesteld.",
        "pl-PL": "Nie skonfigurowano jeszcze żadnych usług DDNS.",
        "pt-PT": "Ainda não foi configurado qualquer serviço DDNS.",
    },
    "no_services_present": {
        "de-DE": "Noch keine Dienste vorhanden.",
        "en-GB": "No services yet.",
        "fr-FR": "Aucun service pour le moment.",
        "es-ES": "Todavía no hay servicios.",
        "it-IT": "Nessun servizio presente.",
        "nl-NL": "Nog geen diensten aanwezig.",
        "pl-PL": "Brak usług.",
        "pt-PT": "Ainda não existem serviços.",
    },
    "service_create": {
        "de-DE": "Dienst anlegen",
        "en-GB": "Create service",
        "fr-FR": "Créer un service",
        "es-ES": "Crear servicio",
        "it-IT": "Crea servizio",
        "nl-NL": "Dienst aanmaken",
        "pl-PL": "Utwórz usługę",
        "pt-PT": "Criar serviço",
    },
    "service_edit": {
        "de-DE": "Dienst bearbeiten",
        "en-GB": "Edit service",
        "fr-FR": "Modifier le service",
        "es-ES": "Editar servicio",
        "it-IT": "Modifica servizio",
        "nl-NL": "Dienst bewerken",
        "pl-PL": "Edytuj usługę",
        "pt-PT": "Editar serviço",
    },
    "display_name": {
        "de-DE": "Anzeigename",
        "en-GB": "Display name",
        "fr-FR": "Nom affiché",
        "es-ES": "Nombre visible",
        "it-IT": "Nome visualizzato",
        "nl-NL": "Weergavenaam",
        "pl-PL": "Nazwa wyświetlana",
        "pt-PT": "Nome apresentado",
    },
    "password_saved_hint": {
        "de-DE": "Gespeichertes Passwort bleibt erhalten, wenn das Feld leer bleibt.",
        "en-GB": "The saved password is kept if this field stays empty.",
        "fr-FR": "Le mot de passe enregistré est conservé si ce champ reste vide.",
        "es-ES": "La contraseña guardada se mantiene si este campo queda vacío.",
        "it-IT": "La password salvata viene mantenuta se questo campo resta vuoto.",
        "nl-NL": "Het opgeslagen wachtwoord blijft behouden als dit veld leeg blijft.",
        "pl-PL": "Zapisane hasło zostanie zachowane, jeśli to pole pozostanie puste.",
        "pt-PT": "A palavra-passe guardada mantém-se se este campo ficar vazio.",
    },
    "password_missing_hint": {
        "de-DE": "Noch kein Passwort gespeichert.",
        "en-GB": "No password has been saved yet.",
        "fr-FR": "Aucun mot de passe n'a encore été enregistré.",
        "es-ES": "Todavía no se ha guardado ninguna contraseña.",
        "it-IT": "Nessuna password ancora salvata.",
        "nl-NL": "Er is nog geen wachtwoord opgeslagen.",
        "pl-PL": "Nie zapisano jeszcze hasła.",
        "pt-PT": "Ainda não foi guardada nenhuma palavra-passe.",
    },
    "enable_service": {
        "de-DE": "Dienst aktivieren",
        "en-GB": "Enable service",
        "fr-FR": "Activer le service",
        "es-ES": "Activar servicio",
        "it-IT": "Attiva servizio",
        "nl-NL": "Dienst inschakelen",
        "pl-PL": "Włącz usługę",
        "pt-PT": "Ativar serviço",
    },
    "save": {
        "de-DE": "Speichern",
        "en-GB": "Save",
        "fr-FR": "Enregistrer",
        "es-ES": "Guardar",
        "it-IT": "Salva",
        "nl-NL": "Opslaan",
        "pl-PL": "Zapisz",
        "pt-PT": "Guardar",
    },
    "setup_saved": {
        "de-DE": "Setup gespeichert.",
        "en-GB": "Setup saved.",
        "fr-FR": "Configuration enregistrée.",
        "es-ES": "Configuración guardada.",
        "it-IT": "Configurazione salvata.",
        "nl-NL": "Instellingen opgeslagen.",
        "pl-PL": "Konfiguracja zapisana.",
        "pt-PT": "Configuração guardada.",
    },
    "interval_minutes": {
        "de-DE": "Intervall in Minuten",
        "en-GB": "Interval in minutes",
        "fr-FR": "Intervalle en minutes",
        "es-ES": "Intervalo en minutos",
        "it-IT": "Intervallo in minuti",
        "nl-NL": "Interval in minuten",
        "pl-PL": "Interwał w minutach",
        "pt-PT": "Intervalo em minutos",
    },
    "boot_delay_seconds": {
        "de-DE": "Startverzögerung nach Boot in Sekunden",
        "en-GB": "Startup delay after boot in seconds",
        "fr-FR": "Délai de démarrage après boot en secondes",
        "es-ES": "Retraso de arranque tras el inicio en segundos",
        "it-IT": "Ritardo di avvio dopo il boot in secondi",
        "nl-NL": "Opstartvertraging na boot in seconden",
        "pl-PL": "Opóźnienie startu po uruchomieniu w sekundach",
        "pt-PT": "Atraso de arranque após boot em segundos",
    },
    "request_timeout_seconds": {
        "de-DE": "Request-Timeout in Sekunden",
        "en-GB": "Request timeout in seconds",
        "fr-FR": "Délai d'attente des requêtes en secondes",
        "es-ES": "Tiempo de espera de la petición en segundos",
        "it-IT": "Timeout richiesta in secondi",
        "nl-NL": "Request-time-out in seconden",
        "pl-PL": "Limit czasu żądania w sekundach",
        "pt-PT": "Timeout do pedido em segundos",
    },
    "retry_count": {
        "de-DE": "Anzahl Retries pro Lauf",
        "en-GB": "Number of retries per run",
        "fr-FR": "Nombre de tentatives par exécution",
        "es-ES": "Número de reintentos por ejecución",
        "it-IT": "Numero di tentativi per esecuzione",
        "nl-NL": "Aantal retries per run",
        "pl-PL": "Liczba ponowień na uruchomienie",
        "pt-PT": "Número de tentativas por execução",
    },
    "retry_delay_seconds": {
        "de-DE": "Wartezeit zwischen Retries in Sekunden",
        "en-GB": "Delay between retries in seconds",
        "fr-FR": "Délai entre les tentatives en secondes",
        "es-ES": "Espera entre reintentos en segundos",
        "it-IT": "Attesa tra i tentativi in secondi",
        "nl-NL": "Wachttijd tussen retries in seconden",
        "pl-PL": "Opóźnienie między ponowieniami w sekundach",
        "pt-PT": "Espera entre tentativas em segundos",
    },
    "audit_log_lines": {
        "de-DE": "Audit-Log-Zeilen im Dashboard",
        "en-GB": "Audit log lines in dashboard",
        "fr-FR": "Lignes du journal d'audit dans le tableau de bord",
        "es-ES": "Líneas del registro de auditoría en el panel",
        "it-IT": "Righe del log di audit nel dashboard",
        "nl-NL": "Auditlogregels in dashboard",
        "pl-PL": "Wiersze logu audytu na pulpicie",
        "pt-PT": "Linhas de registo de auditoria no painel",
    },
    "ipv4_sources": {
        "de-DE": "IPv4-Quellen, eine URL pro Zeile",
        "en-GB": "IPv4 sources, one URL per line",
        "fr-FR": "Sources IPv4, une URL par ligne",
        "es-ES": "Fuentes IPv4, una URL por línea",
        "it-IT": "Sorgenti IPv4, un URL per riga",
        "nl-NL": "IPv4-bronnen, één URL per regel",
        "pl-PL": "Źródła IPv4, jeden URL w wierszu",
        "pt-PT": "Fontes IPv4, um URL por linha",
    },
    "ipv6_sources": {
        "de-DE": "IPv6-Quellen, eine URL pro Zeile",
        "en-GB": "IPv6 sources, one URL per line",
        "fr-FR": "Sources IPv6, une URL par ligne",
        "es-ES": "Fuentes IPv6, una URL por línea",
        "it-IT": "Sorgenti IPv6, un URL per riga",
        "nl-NL": "IPv6-bronnen, één URL per regel",
        "pl-PL": "Źródła IPv6, jeden URL w wierszu",
        "pt-PT": "Fontes IPv6, um URL por linha",
    },
    "mdns_hostname": {
        "de-DE": "mDNS-Hostname",
        "en-GB": "mDNS hostname",
        "fr-FR": "Nom d'hôte mDNS",
        "es-ES": "Nombre de host mDNS",
        "it-IT": "Hostname mDNS",
        "nl-NL": "mDNS-hostnaam",
        "pl-PL": "Nazwa hosta mDNS",
        "pt-PT": "Nome do host mDNS",
    },
    "only_update_on_change": {
        "de-DE": "Nur bei echter IP-Änderung Provider aktualisieren",
        "en-GB": "Only update provider on real IP change",
        "fr-FR": "Mettre à jour le fournisseur uniquement en cas de vrai changement d'IP",
        "es-ES": "Actualizar el proveedor solo si la IP cambia de verdad",
        "it-IT": "Aggiorna il provider solo in caso di reale cambio IP",
        "nl-NL": "Provider alleen bij echte IP-wijziging updaten",
        "pl-PL": "Aktualizuj dostawcę tylko przy rzeczywistej zmianie IP",
        "pt-PT": "Atualizar o fornecedor apenas em caso de alteração real do IP",
    },
    "mdns_enabled": {
        "de-DE": "mDNS-Eintrag in Avahi pflegen",
        "en-GB": "Maintain mDNS entry in Avahi",
        "fr-FR": "Maintenir l'entrée mDNS dans Avahi",
        "es-ES": "Mantener la entrada mDNS en Avahi",
        "it-IT": "Mantenere la voce mDNS in Avahi",
        "nl-NL": "mDNS-vermelding in Avahi bijhouden",
        "pl-PL": "Utrzymuj wpis mDNS w Avahi",
        "pt-PT": "Manter entrada mDNS no Avahi",
    },
    "local_proxy_enabled": {
        "de-DE": "Lokalen Proxy-Host für http://{hostname} anlegen, falls NPM vorhanden ist",
        "en-GB": "Create local proxy host for http://{hostname} if NPM is available",
        "fr-FR": "Créer un hôte proxy local pour http://{hostname} si NPM est disponible",
        "es-ES": "Crear host proxy local para http://{hostname} si NPM está disponible",
        "it-IT": "Crea un host proxy locale per http://{hostname} se NPM è disponibile",
        "nl-NL": "Lokale proxyhost voor http://{hostname} aanmaken als NPM beschikbaar is",
        "pl-PL": "Utwórz lokalny host proxy dla http://{hostname}, jeśli NPM jest dostępny",
        "pt-PT": "Criar host proxy local para http://{hostname} se o NPM estiver disponível",
    },
    "service_created": {
        "de-DE": "service created: {hostname}",
        "en-GB": "service created: {hostname}",
        "fr-FR": "service created: {hostname}",
        "es-ES": "service created: {hostname}",
        "it-IT": "service created: {hostname}",
        "nl-NL": "service created: {hostname}",
        "pl-PL": "service created: {hostname}",
        "pt-PT": "service created: {hostname}",
    },
}

PANEL_DIR = Path(__file__).resolve().parent
BRANDING_FILES = {
    "login_logo": ["Login logo.png", "Login logo.jpg", "Login logo.jpeg", "Login logo.webp", "Login logo.bmp", "Symbol überschrift 1.png"],
    "site_logo": ["Symbol überschrift 1.png"],
    "favicon": ["Symbol website.png"],
    "signature": ["Signatur 2.png", "Signatur 2.jpg", "Signatur 2.jpeg", "Signatur 2.webp", "Signatur 2.bmp", "Signatur.png"],
    "background": ["background.png", "background.jpg", "background.jpeg", "background.webp", "background.bmp"],
}

PROVIDER_SPECS = {
    "dynu": {
        "label": "Dynu",
        "hostname_placeholder": "z. B. meinhost.freeddns.org",
        "username_label": "Dynu Benutzername",
        "password_label": "Dynu Passwort",
        "show_username": True,
        "require_username": True,
        "help": "Für Dynu werden Benutzername und Passwort benötigt.",
        "ip_mode_help": {
            "ipv4": "IPv4 aktualisiert den A-Record.",
            "ipv6": "IPv6 aktualisiert den AAAA-Record über myipv6.",
            "dual": "Dual Stack aktualisiert A und AAAA gemeinsam.",
        },
        "create_error": "Bitte alle Dynu-Pflichtfelder ausfüllen.",
        "update_error": "Bitte den Dynu-Benutzernamen eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
    "duckdns": {
        "label": "DuckDNS",
        "hostname_placeholder": "z. B. meinname oder meinname.duckdns.org",
        "username_label": "Benutzername",
        "password_label": "DuckDNS Token",
        "show_username": False,
        "require_username": False,
        "help": "Für DuckDNS genügt die Subdomain und dein Account-Token. Das Feld Benutzername wird dabei nicht verwendet.",
        "ip_mode_help": {
            "ipv4": "IPv4 setzt nur die IPv4-Adresse bei DuckDNS.",
            "ipv6": "IPv6 setzt nur die IPv6-Adresse bei DuckDNS.",
            "dual": "Dual Stack setzt IPv4 und IPv6 gemeinsam.",
        },
        "create_error": "Bitte den DuckDNS-Token eingeben.",
        "update_error": "Bitte den DuckDNS-Token eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
    "noip": {
        "label": "No-IP",
        "hostname_placeholder": "z. B. meinname.ddns.net",
        "username_label": "No-IP Benutzername",
        "password_label": "No-IP Passwort / DDNS Key",
        "show_username": True,
        "require_username": True,
        "help": "Für No-IP werden Benutzername und Passwort oder alternativ ein DDNS-Key im Passwort-Feld verwendet.",
        "ip_mode_help": {
            "ipv4": "Für IPv4 wird der Host per myip mit einer A-Adresse aktualisiert.",
            "ipv6": "Für IPv6 muss der Host beim Anbieter IPv6-fähig angelegt sein.",
        },
        "create_error": "Bitte die No-IP-Zugangsdaten eingeben.",
        "update_error": "Bitte den No-IP-Benutzernamen eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6"],
    },
    "freedns": {
        "label": "FreeDNS / afraid.org",
        "hostname_placeholder": "z. B. meinhost.mooo.com",
        "username_label": "Benutzername",
        "password_label": "FreeDNS Update-Token oder komplette Update-URL",
        "show_username": False,
        "require_username": False,
        "help": "Für FreeDNS / afraid.org reicht das v2-Update-Token oder direkt die komplette Update-URL aus der Oberfläche.",
        "ip_mode_help": {
            "ipv4": "IPv4 nutzt den normalen FreeDNS-Sync-Endpunkt.",
            "ipv6": "IPv6 nutzt den FreeDNS-v6-Sync-Endpunkt.",
        },
        "create_error": "Bitte das FreeDNS-Update-Token oder die Update-URL eingeben.",
        "update_error": "Bitte das FreeDNS-Update-Token oder die Update-URL eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6"],
    },
    "dynv6": {
        "label": "dynv6",
        "hostname_placeholder": "z. B. meinname.dynv6.net",
        "username_label": "Benutzername",
        "password_label": "dynv6 Token",
        "show_username": False,
        "require_username": False,
        "help": "Für dynv6 werden Hostname/Zone und der HTTP-Token verwendet.",
        "ip_mode_help": {
            "ipv4": "IPv4 aktualisiert die IPv4-Adresse der Zone.",
            "ipv6": "IPv6 aktualisiert die IPv6-Adresse der Zone.",
            "dual": "Dual Stack übermittelt IPv4 und IPv6 in einem Lauf.",
        },
        "create_error": "Bitte den dynv6-Token eingeben.",
        "update_error": "Bitte den dynv6-Token eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
    "desec": {
        "label": "deSEC",
        "hostname_placeholder": "z. B. home.dedyn.io",
        "username_label": "Benutzername",
        "password_label": "deSEC Token",
        "show_username": False,
        "require_username": False,
        "help": "Für deSEC gibst du den vollständigen Hostnamen und einen API-Token an. Das Panel aktualisiert derzeit IPv4.",
        "ip_mode_help": {
            "ipv4": "IPv4 aktualisiert den A-Record.",
            "ipv6": "IPv6 aktualisiert den AAAA-Record.",
            "dual": "Dual Stack aktualisiert A und AAAA gemeinsam.",
        },
        "create_error": "Bitte den deSEC-Token eingeben.",
        "update_error": "Bitte den deSEC-Token eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
    "he": {
        "label": "Hurricane Electric Free DNS",
        "hostname_placeholder": "z. B. dyn.example.com",
        "username_label": "Benutzername",
        "password_label": "HE Dynamic DNS Passwort",
        "show_username": False,
        "require_username": False,
        "help": "Für Hurricane Electric wird der vollständige Hostname plus das in dns.he.net generierte Dynamic-DNS-Passwort verwendet.",
        "ip_mode_help": {
            "ipv4": "IPv4 aktualisiert den A-Record.",
            "ipv6": "IPv6 aktualisiert den AAAA-Record.",
            "dual": "Dual Stack führt getrennte Updates für IPv4 und IPv6 aus.",
        },
        "create_error": "Bitte das Hurricane-Electric-Dynamic-DNS-Passwort eingeben.",
        "update_error": "Bitte das Hurricane-Electric-Dynamic-DNS-Passwort eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
    "cloudns": {
        "label": "ClouDNS",
        "hostname_placeholder": "z. B. home.example.com",
        "username_label": "Benutzername",
        "password_label": "ClouDNS Dynamic URL oder q-Token",
        "show_username": False,
        "require_username": False,
        "help": "Für ClouDNS bitte die Dynamic URL des gewünschten A-Records oder nur den q-Token aus dieser URL eintragen.",
        "ip_mode_help": {
            "ipv4": "Für IPv4 die Dynamic-URL des A-Records bzw. den IPv4-q-Token verwenden.",
            "ipv6": "Für IPv6 die Dynamic-URL des AAAA-Records bzw. den IPv6-q-Token verwenden.",
        },
        "create_error": "Bitte die ClouDNS Dynamic URL oder den q-Token eingeben.",
        "update_error": "Bitte die ClouDNS Dynamic URL oder den q-Token eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6"],
    },
    "ydns": {
        "label": "YDNS",
        "hostname_placeholder": "z. B. meinname.ydns.io",
        "username_label": "YDNS Benutzername / API Username",
        "password_label": "YDNS Passwort / API Passwort",
        "show_username": True,
        "require_username": True,
        "help": "Für YDNS werden Hostname sowie die normalen Zugangsdaten oder die separaten API-Zugangsdaten verwendet.",
        "ip_mode_help": {
            "ipv4": "IPv4 aktualisiert die A-Adresse des Hosts.",
            "ipv6": "IPv6 aktualisiert die AAAA-Adresse des Hosts.",
        },
        "create_error": "Bitte die YDNS-Zugangsdaten eingeben.",
        "update_error": "Bitte den YDNS-Benutzernamen eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6"],
    },
    "ddnss": {
        "label": "ddnss.de",
        "hostname_placeholder": "z. B. meinname.ddnss.de",
        "username_label": "ddnss.de Benutzername",
        "password_label": "ddnss.de Passwort",
        "show_username": True,
        "require_username": True,
        "help": "Für ddnss.de werden Benutzername, Passwort und Hostname verwendet.",
        "ip_mode_help": {
            "ipv4": "IPv4 aktualisiert den A-Record.",
            "ipv6": "IPv6 aktualisiert den AAAA-Record über ip6.",
            "dual": "Dual Stack aktualisiert IPv4 und IPv6 gemeinsam.",
        },
        "create_error": "Bitte die ddnss.de-Zugangsdaten eingeben.",
        "update_error": "Bitte den ddnss.de-Benutzernamen eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
    "netcup_rest": {
        "label": "Netcup REST API",
        "hostname_placeholder": "z. B. mail.knittel-cloud.de",
        "username_label": "Benutzername",
        "password_label": "Netcup API-Key",
        "show_username": False,
        "require_username": False,
        "help": "Für Netcup wird nur der neue API-Key benötigt. Der Key wird geschützt auf dem Server gespeichert; keine Legacy-API verwenden.",
        "ip_mode_help": {
            "ipv4": "IPv4 aktualisiert den passenden A-Record in deiner Netcup-DNS-Zone.",
        },
        "create_error": "Bitte den Netcup API-Key eingeben.",
        "update_error": "Bitte den Netcup API-Key eingeben.",
        "supported_ip_modes": ["ipv4"],
    },
    "cloudflare": {
        "label": "Cloudflare",
        "hostname_placeholder": "z. B. home.example.com",
        "username_label": "Cloudflare Zone ID",
        "password_label": "Cloudflare API Token",
        "show_username": True,
        "require_username": True,
        "help": "Für Cloudflare gibst du den vollständigen Hostnamen, die Zone ID und einen API-Token mit DNS Read und DNS Write an.",
        "ip_mode_help": {
            "ipv4": "IPv4 pflegt nur den A-Record in Cloudflare.",
            "ipv6": "IPv6 pflegt nur den AAAA-Record in Cloudflare.",
            "dual": "Dual Stack legt bzw. aktualisiert A und AAAA gemeinsam an.",
        },
        "create_error": "Bitte Cloudflare Zone ID und API-Token eingeben.",
        "update_error": "Bitte die Cloudflare Zone ID eingeben.",
        "supported_ip_modes": ["ipv4", "ipv6", "dual"],
    },
}


def load_auth() -> dict:
    data = load_json(AUTH_FILE, {})
    return data if isinstance(data, dict) else {}


def normalize_locale(value: str | None) -> str:
    value = (value or "").strip()
    return value if value in SUPPORTED_LOCALES else DEFAULT_LOCALE


def current_locale() -> str:
    session_value = normalize_locale(session.get("locale"))
    cookie_value = normalize_locale(request.cookies.get(LANGUAGE_COOKIE))
    if session_value != DEFAULT_LOCALE or "locale" in session:
        return session_value
    return cookie_value


def t(key: str, **kwargs) -> str:
    locale = current_locale()
    values = TRANSLATIONS.get(key, {})
    text = values.get(locale) or values.get(DEFAULT_LOCALE) or key
    return text.format(**kwargs) if kwargs else text


def locale_options_html(selected: str) -> str:
    return "".join(
        f'<option value="{code}"{" selected" if code == selected else ""}>{html.escape(LOCALE_SHORT_LABELS[code])}</option>'
        for code in SUPPORTED_LOCALES
    )


def locale_flag_html(code: str) -> str:
    return LOCALE_FLAG_SVGS[code]


def locale_compact_html(code: str) -> str:
    return f'{locale_flag_html(code)}<span>{html.escape(LOCALE_SHORT_LABELS[code])}</span>'


def language_selector(next_path: str = "", compact: bool = False) -> str:
    next_value = html.escape(next_path or request.path)
    if compact:
        current = current_locale()
        buttons = "".join(
            f'<button type="submit" name="locale" value="{code}" class="language-menu-item{" active" if code == current else ""}">{locale_compact_html(code)}</button>'
            for code in SUPPORTED_LOCALES
        )
        return (
            '<details class="language-menu">'
            f'<summary class="language-menu-toggle" aria-label="{html.escape(t("language"))}">{locale_compact_html(current)}</summary>'
            '<form method="post" action="/set-language" class="language-menu-list">'
            f'<input type="hidden" name="next" value="{next_value}">'
            f"{buttons}"
            "</form></details>"
        )
    css = "language-form"
    return (
        f'<form method="post" action="/set-language" class="{css}">'
        f'<input type="hidden" name="next" value="{next_value}">'
        f'<label class="sr-only">{html.escape(t("language"))}</label>'
        f'<select name="locale" onchange="this.form.submit()" aria-label="{html.escape(t("language"))}">'
        f"{locale_options_html(current_locale())}"
        "</select></form>"
    )


def save_auth(data: dict) -> None:
    save_json(AUTH_FILE, data)
    try:
        AUTH_FILE.chmod(0o600)
    except Exception:
        pass


def init_auth_defaults() -> None:
    data = load_auth()
    changed = False
    defaults = {
        "username": "",
        "password_hash": "",
        "reset_pin_hash": "",
        "failed_reset_attempts": 0,
        "reset_locked_until": 0,
        "failed_login_attempts": 0,
        "login_locked_until": 0,
        "created_at": "",
        "updated_at": "",
    }
    for key, value in defaults.items():
        if key not in data:
            data[key] = value
            changed = True
    if changed:
        save_auth(data)


def is_auth_configured() -> bool:
    data = load_auth()
    return bool(data.get("username") and data.get("password_hash") and data.get("reset_pin_hash"))


def is_session_valid() -> bool:
    if not session.get("logged_in"):
        return False
    if session.get("remember_me"):
        session.permanent = True
        session["last_seen"] = int(time.time())
        return True
    now = int(time.time())
    last_seen = session.get("last_seen", 0)
    try:
        last_seen = int(last_seen)
    except Exception:
        last_seen = 0
    if now - last_seen > SESSION_TIMEOUT_MINUTES * 60:
        session.clear()
        return False
    session["last_seen"] = now
    session.permanent = False
    return True


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not is_auth_configured():
            return redirect(url_for("setup"), code=303)
        if not is_session_valid():
            return redirect(url_for("login"), code=303)
        return view_func(*args, **kwargs)

    return wrapped


@app.before_request
def enforce_auth():
    open_paths = {"/login", "/setup", "/reset-access", "/factory-reset", "/set-language"}
    path = request.path or "/"
    if not is_auth_configured():
        if path != "/setup":
            return redirect(url_for("setup"), code=303)
        return None
    if path.startswith("/branding/"):
        return None
    if path in open_paths:
        return None
    if not is_session_valid():
        return redirect(url_for("login"), code=303)
    return None


@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://images.emojiterra.com https://img.freepik.com https://flagemoji.net; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response


def nav(active: str) -> str:
    links = [
        ("/", t("dashboard"), active == "dashboard"),
        ("/services", t("services"), active == "services"),
        ("/setup-config", t("setup"), active == "setup-config"),
    ]
    items = []
    for href, label, is_active in links:
        css = "btn secondary active" if is_active else "btn secondary"
        items.append(f'<a class="{css}" href="{href}">{html.escape(label)}</a>')
    items.append(f'<a class="btn secondary" href="/logout">{html.escape(t("logout"))}</a>')
    items.append(language_selector(request.path, compact=True))
    return "".join(items)


def branding_asset_path(key: str) -> Path | None:
    filenames = BRANDING_FILES.get(key)
    if not filenames:
        return None
    if isinstance(filenames, str):
        filenames = [filenames]
    candidates = [
        path
        for filename in filenames
        for path in (PANEL_DIR / "assets" / filename, APP_DIR / "panel" / "assets" / filename)
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def branding_asset_url(key: str) -> str:
    asset_path = branding_asset_path(key)
    if not asset_path:
        return ""
    try:
        version = int(asset_path.stat().st_mtime)
    except Exception:
        version = 0
    return url_for("branding_asset", asset_key=key, v=version)


def branding_context() -> dict[str, str]:
    return {
        "background_url": branding_asset_url("background"),
        "login_logo_url": branding_asset_url("login_logo"),
        "site_logo_url": branding_asset_url("site_logo"),
        "favicon_url": branding_asset_url("favicon"),
        "signature_url": branding_asset_url("signature"),
    }


@app.route("/set-language", methods=["POST"])
def set_language():
    locale = normalize_locale(request.form.get("locale"))
    next_path = (request.form.get("next") or "").strip() or "/"
    session["locale"] = locale
    response = redirect(next_path if next_path.startswith("/") else "/", code=303)
    response.set_cookie(LANGUAGE_COOKIE, locale, max_age=60 * 60 * 24 * REMEMBER_ME_DAYS, samesite="Lax", httponly=False)
    return response


def layout(body: str, active: str = "", page_class: str = "", nav_html: str | None = None, overlay: str = "") -> str:
    return render_template_string(
        BASE,
        body=body,
        nav=nav_html if nav_html is not None else nav(active),
        page_class=page_class,
        overlay=overlay,
        branding=branding_context(),
        locale=current_locale(),
    )


def login_background_preview() -> str:
    return """
<div class="page-head login-preview-head">
<div>
<h1>{dashboard}</h1>
<p class="muted">{status_text}</p>
</div>
<div class="actions-row">
<span class="btn secondary">{run_now}</span>
<span class="btn primary">{add_service}</span>
</div>
</div>
<div class="card">
<div class="kv-grid">
<div class="kv"><span class="kv-label">{current_ip}</span><span>•••.•••.•••.•••</span></div>
<div class="kv"><span class="kv-label">{last_check}</span><span>{last_check_value}</span></div>
<div class="kv"><span class="kv-label">{summary}</span><span>{summary_value}</span></div>
<div class="kv"><span class="kv-label">URL</span><span class="host-badge">http://ddns-panel.local</span></div>
</div>
</div>
<div class="card">
<h2>{ddns_services}</h2>
<table>
<tr><th>{enabled}</th><th>{name}</th><th>{provider}</th><th>{hostname}</th><th>{status}</th><th>{last_ipv4}</th><th>{actions}</th></tr>
<tr><td><input type="checkbox" checked disabled></td><td>Home Gateway</td><td>Dynu</td><td>home.example.net</td><td><span class="badge online">OK</span></td><td>•••.•••.•••.•••</td><td><div class="table-actions"><span class="btn secondary">{edit}</span><span class="btn secondary">{test}</span></div></td></tr>
<tr><td><input type="checkbox" checked disabled></td><td>VPN</td><td>Dynu</td><td>vpn.example.net</td><td><span class="badge offline">{waiting}</span></td><td>•••.•••.•••.•••</td><td><div class="table-actions"><span class="btn secondary">{edit}</span><span class="btn secondary">{test}</span></div></td></tr>
</table>
</div>
""".format(
        dashboard=html.escape(t("dashboard")),
        status_text=html.escape(t("services_manage")),
        run_now=html.escape(t("run_now")),
        add_service=html.escape(t("add_service")),
        current_ip=html.escape(t("current_public_ipv4")),
        last_check=html.escape(t("last_check")),
        last_check_value=html.escape(t("waiting")),
        summary=html.escape(t("summary")),
        summary_value=html.escape("2 Dienste aktiv, 1 Änderung ausstehend" if current_locale() == "de-DE" else "2 services active, 1 change pending"),
        ddns_services=html.escape(t("ddns_services")),
        enabled=html.escape(t("enabled")),
        name=html.escape(t("name")),
        provider=html.escape(t("provider")),
        hostname=html.escape(t("hostname_domain")),
        status=html.escape(t("service_status")),
        last_ipv4=html.escape(t("last_ipv4")),
        actions=html.escape(t("actions")),
        edit=html.escape(t("edit")),
        test=html.escape(t("test")),
        waiting=html.escape(t("waiting")),
    )


def format_public_urls(setup_data: dict) -> str:
    local_host = setup_data["mdns_hostname"]
    lan_ip = load_status().get("local_ip", "") or get_primary_lan_ip()
    ip_url = f"http://{lan_ip}:{PANEL_PORT}" if lan_ip else f"http://SERVER-IP:{PANEL_PORT}"
    proxy_url = f"http://{local_host}" if setup_data.get("local_proxy_enabled") else f"http://{local_host}:{PANEL_PORT}"
    return (
        '<div class="card">'
        "<h2>Erreichbarkeit</h2>"
        f'<div class="kv"><span class="kv-label">mDNS</span><span class="host-badge">{html.escape(proxy_url)}</span></div>'
        f'<div class="kv"><span class="kv-label">Direkt</span><span class="host-badge">{html.escape(ip_url)}</span></div>'
        "</div>"
    )


def provider_option_tags(selected: str) -> str:
    providers = [(key, value["label"]) for key, value in PROVIDER_SPECS.items()]
    return "".join(
        f'<option value="{value}"{" selected" if value == selected else ""}>{label}</option>'
        for value, label in providers
    )


def get_provider_spec(provider: str) -> dict:
    return PROVIDER_SPECS.get(provider, PROVIDER_SPECS["dynu"])


def provider_display_name(provider: str) -> str:
    return get_provider_spec(provider)["label"]


def ip_mode_option_tags(provider: str, selected: str) -> str:
    labels = {"ipv4": "IPv4", "ipv6": "IPv6", "dual": "Dual Stack"}
    supported = get_provider_spec(provider).get("supported_ip_modes", ["ipv4"])
    return "".join(
        f'<option value="{mode}"{" selected" if mode == selected else ""}>{labels[mode]}</option>'
        for mode in supported
    )


def ip_mode_display_name(ip_mode: str) -> str:
    return {"ipv4": "IPv4", "ipv6": "IPv6", "dual": "Dual Stack"}.get(ip_mode, ip_mode)


@app.route("/logs/download")
@login_required
def logs_download():
    lines = tail_audit_log(load_setup()["log_lines"])
    payload = "\n".join(lines) + ("\n" if lines else "")
    return app.response_class(
        payload,
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=ddns-panel-audit.log"},
    )


@app.route("/branding/<asset_key>")
def branding_asset(asset_key: str):
    asset_path = branding_asset_path(asset_key)
    if not asset_path:
        abort(404)
    mimetype = "image/png" if asset_path.suffix.lower() == ".png" else None
    return send_file(asset_path, mimetype=mimetype, conditional=True, max_age=3600)


@app.route("/favicon.ico")
def favicon():
    asset_path = branding_asset_path("favicon")
    if not asset_path:
        abort(404)
    return send_file(asset_path, mimetype="image/png", conditional=True, max_age=3600)


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if is_auth_configured():
        return redirect(url_for("login"), code=303)
    error = ""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        reset_pin = (request.form.get("reset_pin") or "").strip()
        if not username or not password or not password2 or not reset_pin:
            error = t("fill_all_fields")
        elif password != password2:
            error = t("passwords_do_not_match")
        elif len(password) < 8:
            error = t("password_min_length")
        elif len(reset_pin) < 4:
            error = t("pin_min_length")
        else:
            now = now_iso()
            save_auth(
                {
                    "username": username,
                    "password_hash": generate_password_hash(password),
                    "reset_pin_hash": generate_password_hash(reset_pin),
                    "failed_reset_attempts": 0,
                    "reset_locked_until": 0,
                    "failed_login_attempts": 0,
                    "login_locked_until": 0,
                    "created_at": now,
                    "updated_at": now,
                }
            )
            write_audit_log(f"{username} completed initial panel setup")
            return redirect(url_for("login"), code=303)
    body = f"""
<h1>{html.escape(t("initial_setup_title"))}</h1>
<div class="card">
<p>{html.escape(t("no_access_configured"))}</p>
<form method="post" class="form-grid">
<div><label>{html.escape(t("username"))}</label><input type="text" name="username" required></div>
<div><label>{html.escape(t("password"))}</label><input type="password" name="password" required></div>
<div><label>{html.escape(t("repeat_password"))}</label><input type="password" name="password2" required></div>
<div><label>{html.escape(t("reset_pin"))}</label><input type="password" name="reset_pin" required></div>
<button class="primary" type="submit">{html.escape(t("complete_setup"))}</button>
{"<p>" + html.escape(error) + "</p>" if error else ""}
</form>
</div>
"""
    return layout(body)


@app.route("/login", methods=["GET", "POST"])
def login():
    if not is_auth_configured():
        return redirect(url_for("setup"), code=303)
    if is_session_valid():
        return redirect(url_for("index"), code=303)
    error = ""
    info = ""
    remember_me = False
    auth = load_auth()
    now_ts = int(time.time())
    locked_until = int(auth.get("login_locked_until", 0) or 0)
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        remember_me = request.form.get("remember_me") == "on"
        if locked_until > now_ts:
            remaining = max(1, (locked_until - now_ts + 59) // 60)
            info = t("login_locked", minutes=remaining)
        elif not username or not password:
            error = t("enter_username_password")
        elif username == auth.get("username") and check_password_hash(auth.get("password_hash", ""), password):
            auth["failed_login_attempts"] = 0
            auth["login_locked_until"] = 0
            save_auth(auth)
            session.clear()
            session["logged_in"] = True
            session["username"] = username
            session["remember_me"] = remember_me
            session["last_seen"] = int(time.time())
            session.permanent = remember_me
            write_audit_log(f"{username} logged in")
            return redirect(url_for("index"), code=303)
        else:
            attempts = int(auth.get("failed_login_attempts", 0) or 0) + 1
            auth["failed_login_attempts"] = attempts
            if attempts >= LOGIN_MAX_ATTEMPTS:
                auth["failed_login_attempts"] = 0
                auth["login_locked_until"] = now_ts + LOGIN_LOCK_SECONDS
                save_auth(auth)
                info = t("login_locked", minutes=max(1, LOGIN_LOCK_SECONDS // 60))
            else:
                save_auth(auth)
                error = t("invalid_login_attempts_left", remaining=LOGIN_MAX_ATTEMPTS - attempts)
            write_audit_log(f"invalid login attempt for username={username or 'empty'}")
    login_logo_url = branding_asset_url("login_logo")
    brand_header = (
        f'<img class="login-logo" src="{html.escape(login_logo_url)}" alt="DDNS Panel">'
        if login_logo_url
        else "<h1>Login</h1>"
    )
    overlay = f"""
<div class="login-overlay">
  <div class="login-dialog card">
    <div class="login-toolbar">{language_selector('/login')}</div>
    <div class="login-brand">{brand_header}</div>
    <form method="post" class="form-grid">
      <div><label>{html.escape(t("username"))}</label><input type="text" name="username" required autofocus></div>
      <div><label>{html.escape(t("password"))}</label><input type="password" name="password" required></div>
      <label><input type="checkbox" name="remember_me" {"checked" if remember_me else ""}> {html.escape(t("remember_me"))}</label>
      <div class="actions-row">
        <button class="primary" type="submit">{html.escape(t("sign_in"))}</button>
        <a class="btn secondary" href="/reset-access">{html.escape(t("reset_access"))}</a>
      </div>
      {"<div class='notice warn'>" + html.escape(info) + "</div>" if info else ""}
      {"<p>" + html.escape(error) + "</p>" if error else ""}
    </form>
  </div>
</div>
"""
    return layout(
        login_background_preview(),
        page_class="page-login",
        nav_html=language_selector("/login", compact=True) + f'<span class="nav-chip">{html.escape(t("panel_locked"))}</span>',
        overlay=overlay,
    )


@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    write_audit_log(f"{username} logged out")
    return redirect(url_for("login"), code=303)


@app.route("/reset-access", methods=["GET", "POST"])
def reset_access():
    if not is_auth_configured():
        return redirect(url_for("setup"), code=303)
    auth = load_auth()
    now_ts = int(time.time())
    locked_until = int(auth.get("reset_locked_until", 0) or 0)
    error = ""
    info = ""
    if request.method == "POST":
        reset_pin = (request.form.get("reset_pin") or "").strip()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""
        if locked_until > now_ts:
            info = t("reset_locked", minutes=max(1, (locked_until - now_ts + 59) // 60))
        elif not reset_pin or not username or not password or not password2:
            error = t("fill_all_fields")
        elif password != password2:
            error = t("passwords_do_not_match")
        elif len(password) < 8:
            error = t("password_min_length")
        elif not check_password_hash(auth.get("reset_pin_hash", ""), reset_pin):
            attempts = int(auth.get("failed_reset_attempts", 0) or 0) + 1
            auth["failed_reset_attempts"] = attempts
            if attempts >= RESET_PIN_MAX_ATTEMPTS:
                auth["failed_reset_attempts"] = 0
                auth["reset_locked_until"] = now_ts + RESET_PIN_LOCK_SECONDS
                save_auth(auth)
                info = t("reset_locked", minutes=max(1, RESET_PIN_LOCK_SECONDS // 60))
            else:
                save_auth(auth)
                error = t("invalid_reset_pin_attempts_left", remaining=RESET_PIN_MAX_ATTEMPTS - attempts)
            write_audit_log("invalid reset PIN attempt")
        else:
            auth["username"] = username
            auth["password_hash"] = generate_password_hash(password)
            auth["failed_reset_attempts"] = 0
            auth["reset_locked_until"] = 0
            auth["updated_at"] = now_iso()
            save_auth(auth)
            session.clear()
            write_audit_log(f"{username} reset panel access via reset PIN")
            return redirect(url_for("login"), code=303)
    body = f"""
<h1>{html.escape(t("reset_access"))}</h1>
<div class="card form-card">
<form method="post" class="form-grid">
<div><label>{html.escape(t("reset_pin"))}</label><input type="password" name="reset_pin" required></div>
<div><label>{html.escape(t("new_username"))}</label><input type="text" name="username" required></div>
<div><label>{html.escape(t("new_password"))}</label><input type="password" name="password" required></div>
<div><label>{html.escape(t("repeat_new_password"))}</label><input type="password" name="password2" required></div>
<div class="actions-row">
<button class="primary" type="submit">{html.escape(t("reset_access"))}</button>
<a class="btn secondary" href="/login">{html.escape(t("back"))}</a>
</div>
{"<div class='notice warn'>" + html.escape(info) + "</div>" if info else ""}
{"<p>" + html.escape(error) + "</p>" if error else ""}
</form>
</div>
<div class="card warn">
<h2>{html.escape(t("factory_reset"))}</h2>
<p>{html.escape(t("factory_reset_warning"))}</p>
<a class="btn delete" href="/factory-reset">{html.escape(t("open_factory_reset"))}</a>
</div>
"""
    return layout(body)


@app.route("/factory-reset", methods=["GET", "POST"])
def factory_reset():
    error = ""
    if request.method == "POST":
        if (request.form.get("confirmation") or "").strip() != "WERKSRESET":
            error = t("factory_reset_confirm_exact")
        else:
            remove_panel_runtime()
            write_audit_log("factory reset executed")
            session.clear()
            return redirect(url_for("setup"), code=303)
    body = f"""
<h1>{html.escape(t("factory_reset"))}</h1>
<div class="card warn">
<p>{html.escape(t("items_deleted"))}</p>
<ul>
<li>{html.escape(t("panel_access"))}</li>
<li>{html.escape(t("ddns_entries"))}</li>
<li>{html.escape(t("provider_secrets"))}</li>
<li>{html.escape(t("local_status_logs"))}</li>
</ul>
<form method="post" class="form-grid">
<div><label>{html.escape(t("confirm_text"))}</label><input type="text" name="confirmation" required></div>
<div class="actions-row">
<button class="delete" type="submit">{html.escape(t("run_factory_reset"))}</button>
<a class="btn secondary" href="/reset-access">{html.escape(t("back"))}</a>
</div>
{"<p>" + html.escape(error) + "</p>" if error else ""}
</form>
</div>
"""
    return layout(body)


@app.route("/")
@login_required
def index():
    setup_data = load_setup()
    entries = load_entries()["entries"]
    status = load_status()
    rows = []
    for entry in entries:
        entry_status = status["entries"].get(entry["id"], {})
        badge_class = "online" if entry_status.get("ok") else "offline"
        badge_text = "OK" if entry_status.get("ok") else (t("error_short") if entry_status.get("last_error") else t("waiting"))
        hostnames_html = "<br>".join(html.escape(hostname) for hostname in entry_hostnames(entry)) or "-"
        rows.append(
            f"""
<tr>
<td><form method="post" action="/services/toggle" data-async-toggle="1"><input type="hidden" name="entry_id" value="{entry['id']}"><input type="checkbox" onchange="this.form.requestSubmit()" {"checked" if entry.get("enabled") else ""}></form></td>
<td>{html.escape(entry['name'])}</td>
<td>{html.escape(provider_display_name(entry['provider']))}</td>
<td>{html.escape(ip_mode_display_name(entry.get('ip_mode', 'ipv4')))}</td>
<td>{hostnames_html}</td>
<td><span class="badge {badge_class}">{badge_text}</span></td>
<td>{html.escape(entry_status.get('last_public_ipv4', '-'))}</td>
<td>{html.escape(entry_status.get('last_public_ipv6', '-'))}</td>
<td>{html.escape(entry_status.get('last_update_at', '-'))}</td>
<td class="table-actions-cell"><div class="table-actions"><a class="btn secondary" href="/services/{entry['id']}/edit">{html.escape(t("edit"))}</a><form method="post" action="/services/run" data-async-run="1"><input type="hidden" name="entry_id" value="{entry['id']}"><input type="hidden" name="return_to" value="/"><button class="btn secondary" type="submit">{html.escape(t("test"))}</button></form></div></td>
</tr>
"""
        )
    body = f"""
<div class="page-head">
<div>
<h1>{html.escape(t("dashboard"))}</h1>
</div>
</div>
<div class="card">
<details>
<summary><strong>{html.escape(t("status"))}</strong></summary>
<div style="margin-top:16px;">
<div class="kv-grid">
<div class="kv"><span class="kv-label">{html.escape(t("current_public_ipv4"))}</span><span>{html.escape(status.get('current_public_ipv4') or '-')}</span></div>
<div class="kv"><span class="kv-label">{html.escape(t("current_public_ipv6"))}</span><span>{html.escape(status.get('current_public_ipv6') or '-')}</span></div>
<div class="kv"><span class="kv-label">{html.escape(t("last_check"))}</span><span>{html.escape(status.get('last_check_at') or '-')}</span></div>
<div class="kv"><span class="kv-label">{html.escape(t("last_change"))}</span><span>{html.escape(status.get('last_change_at') or '-')}</span></div>
<div class="kv"><span class="kv-label">{html.escape(t("summary"))}</span><span>{html.escape(status.get('last_run_summary') or '-')}</span></div>
<div class="kv"><span class="kv-label">{html.escape(t("update_interval"))}</span><span>{html.escape(t("every_minutes", minutes=setup_data['interval_minutes']))}</span></div>
<div class="kv"><span class="kv-label">{html.escape(t("panel_process"))}</span><span>{html.escape(' '.join(build_update_command()))}</span></div>
</div>
</div>
</details>
</div>
<div class="card">
<h2>{html.escape(t("ddns_services"))}</h2>
<table>
<tr><th>{html.escape(t("enabled"))}</th><th>{html.escape(t("name"))}</th><th>{html.escape(t("provider"))}</th><th>{html.escape(t("ip_mode"))}</th><th>{html.escape(t("hostname_domain"))}</th><th>{html.escape(t("service_status"))}</th><th>{html.escape(t("last_ipv4"))}</th><th>{html.escape(t("last_ipv6"))}</th><th>{html.escape(t("last_update"))}</th><th>{html.escape(t("actions"))}</th></tr>
{''.join(rows) if rows else f'<tr><td colspan="10">{html.escape(t("no_services_configured"))}</td></tr>'}
</table>
<div class="table-footer-actions"><a class="btn secondary" href="/logs/download">{html.escape(t("download_logs"))}</a></div>
</div>
"""
    return layout(body, active="dashboard")


@app.route("/run-now", methods=["POST"])
@login_required
def run_now():
    ok, output = run_panel_update()
    write_audit_log(f"manual global update run: {'ok' if ok else 'error'}")
    return redirect(url_for("services", notice=output[:400], level="ok" if ok else "error"), code=303)


@app.route("/services")
@login_required
def services():
    entries = load_entries()["entries"]
    status = load_status()
    notice = request.args.get("notice", "")
    level = request.args.get("level", "ok")
    rows = []
    for entry in entries:
        entry_status = status["entries"].get(entry["id"], {})
        host_statuses = entry_status.get("hosts", {}) if isinstance(entry_status.get("hosts", {}), dict) else {}
        host_rows = []
        for hostname in entry_hostnames(entry):
            host_status = host_statuses.get(hostname, {})
            host_result = host_status.get("last_result", "-")
            host_rows.append(f"{html.escape(hostname)}: {html.escape(str(host_result))}")
        hostnames_html = "<br>".join(host_rows) or "-"
        rows.append(
            f"""
<tr>
<td><form method="post" action="/services/toggle"><input type="hidden" name="entry_id" value="{entry['id']}"><input type="checkbox" onchange="this.form.submit()" {"checked" if entry.get("enabled") else ""}></form></td>
<td>{html.escape(entry['name'])}</td>
<td>{html.escape(provider_display_name(entry['provider']))}</td>
<td>{html.escape(ip_mode_display_name(entry.get('ip_mode', 'ipv4')))}</td>
<td>{hostnames_html}</td>
<td>{html.escape(entry_status.get('last_result', '-'))}</td>
<td>{html.escape(entry_status.get('last_error', '-'))}</td>
<td class="table-actions-cell"><div class="table-actions"><a class="btn secondary" href="/services/{entry['id']}/edit">{html.escape(t("edit"))}</a><form method="post" action="/services/run"><input type="hidden" name="entry_id" value="{entry['id']}"><button class="btn secondary" type="submit">{html.escape(t("test"))}</button></form><form method="post" action="/services/delete" onsubmit="return confirm('{html.escape(t("confirm_delete"))}');"><input type="hidden" name="entry_id" value="{entry['id']}"><button class="delete" type="submit">{html.escape(t("delete"))}</button></form></div></td>
</tr>
"""
        )
    notice_html = ""
    if notice:
        notice_html = f"<div class='notice {'warn' if level == 'error' else 'ok'}'>{html.escape(notice)}</div>"
    body = f"""
<div class="page-head">
<div><h1>{html.escape(t("services"))}</h1><p class="muted">{html.escape(t("services_manage"))}</p></div>
<div class="actions-row"><form method="post" action="/run-now"><button class="primary" type="submit">{html.escape(t("run_now"))}</button></form><a class="btn primary" href="/services/new">{html.escape(t("add_service"))}</a></div>
</div>
{notice_html}
<div class="card">
<table>
<tr><th>{html.escape(t("enabled"))}</th><th>{html.escape(t("name"))}</th><th>{html.escape(t("provider"))}</th><th>{html.escape(t("ip_mode"))}</th><th>{html.escape(t("hostname_domain"))}</th><th>{html.escape(t("last_result"))}</th><th>{html.escape(t("last_error"))}</th><th>{html.escape(t("actions"))}</th></tr>
{''.join(rows) if rows else f'<tr><td colspan="8">{html.escape(t("no_services_present"))}</td></tr>'}
</table>
</div>
"""
    return layout(body, active="services")


def service_form(entry: dict | None = None, error: str = "", secret_override: dict | None = None) -> str:
    entry = entry or {
        "id": "",
        "name": "",
        "enabled": True,
        "provider": "dynu",
        "ip_mode": "dual",
        "hostname": "",
        "hostnames": [],
    }
    secret = secret_override or (get_entry_secret(entry["id"]) if entry.get("id") else {"username": "", "password": ""})
    masked_hint = t("password_saved_hint") if secret.get("password") else t("password_missing_hint")
    title = t("service_edit") if entry.get("id") else t("service_create")
    provider = entry.get("provider", "dynu")
    ip_mode = entry.get("ip_mode", "ipv4")
    spec = get_provider_spec(provider)
    hostname_placeholder = spec["hostname_placeholder"]
    username_label = spec["username_label"]
    password_label = spec["password_label"]
    provider_help = spec["help"]
    ip_mode_help = spec.get("ip_mode_help", {}).get(ip_mode, "")
    username_required = " required" if spec["require_username"] else ""
    provider_specs_json = json.dumps(PROVIDER_SPECS)
    username_value = html.escape(secret.get("username", ""))
    hostnames_value = html.escape("\n".join(entry_hostnames(entry)))
    return f"""
<h1>{html.escape(title)}</h1>
<div class="card form-card">
<form method="post" class="form-grid">
<div><label>{html.escape(t("display_name"))}</label><input type="text" name="name" value="{html.escape(entry.get('name', ''))}" required></div>
<div><label>{html.escape(t("provider"))}</label><select name="provider" data-provider-select>{provider_option_tags(provider)}</select></div>
<div><label>{html.escape(t("ip_mode"))}</label><select name="ip_mode" data-ip-mode-select>{ip_mode_option_tags(provider, ip_mode)}</select></div>
<div><label>{html.escape(t("hostname_domain"))}</label><textarea name="hostnames" rows="5" placeholder="{html.escape(hostname_placeholder)}" required data-hostname-input>{hostnames_value}</textarea><p class="muted">Ein Hostname oder eine Domain pro Zeile.</p></div>
<div class="provider-username-row"{" style='display:none;'" if not spec["show_username"] else ""}><label data-username-label>{html.escape(username_label)}</label><input type="text" name="username" value="{username_value}"{username_required} data-username-input></div>
<div><label data-password-label>{password_label}</label><input type="password" name="password" value="" data-password-input></div>
<p class="muted" data-provider-help>{html.escape(provider_help)}</p>
<p class="muted" data-ip-mode-help>{html.escape(ip_mode_help)}</p>
<p class="muted">{html.escape(masked_hint)}</p>
<label><input type="checkbox" name="enabled" {"checked" if entry.get("enabled", True) else ""}> {html.escape(t("enable_service"))}</label>
<div class="actions-row">
<button class="primary" type="submit">{html.escape(t("save"))}</button>
<a class="btn secondary" href="/services">{html.escape(t("back"))}</a>
</div>
{"<p>" + html.escape(error) + "</p>" if error else ""}
</form>
</div>
<script>
(() => {{
  const form = document.currentScript.previousElementSibling;
  if (!form) return;
  const providerSelect = form.querySelector('[data-provider-select]');
  const usernameRow = form.querySelector('.provider-username-row');
  const usernameInput = form.querySelector('[data-username-input]');
  const usernameLabel = form.querySelector('[data-username-label]');
  const passwordLabel = form.querySelector('[data-password-label]');
  const hostnameInput = form.querySelector('[data-hostname-input]');
  const providerHelp = form.querySelector('[data-provider-help]');
  const ipModeHelp = form.querySelector('[data-ip-mode-help]');
  const ipModeSelect = form.querySelector('[data-ip-mode-select]');
  const providerSpecs = {provider_specs_json};
  const applyProviderState = (preserveSelection = true) => {{
    const spec = providerSpecs[providerSelect.value] || providerSpecs.dynu;
    usernameRow.style.display = spec.show_username ? '' : 'none';
    usernameInput.required = !!spec.require_username;
    usernameLabel.textContent = spec.username_label;
    passwordLabel.textContent = spec.password_label;
    hostnameInput.placeholder = spec.hostname_placeholder;
    providerHelp.textContent = spec.help;
    const previous = preserveSelection ? ipModeSelect.value : '';
    ipModeSelect.innerHTML = '';
    (spec.supported_ip_modes || ['ipv4']).forEach((mode) => {{
      const option = document.createElement('option');
      option.value = mode;
      option.textContent = mode === 'ipv4' ? 'IPv4' : (mode === 'ipv6' ? 'IPv6' : 'Dual Stack');
      if (mode === previous) {{
        option.selected = true;
      }}
      ipModeSelect.appendChild(option);
    }});
    if (!Array.from(ipModeSelect.options).some((option) => option.selected)) {{
      ipModeSelect.options[0].selected = true;
    }}
    ipModeHelp.textContent = (spec.ip_mode_help && spec.ip_mode_help[ipModeSelect.value]) || '';
  }};
  providerSelect.addEventListener('change', () => applyProviderState(false));
  ipModeSelect.addEventListener('change', () => {{
    const spec = providerSpecs[providerSelect.value] || providerSpecs.dynu;
    ipModeHelp.textContent = (spec.ip_mode_help && spec.ip_mode_help[ipModeSelect.value]) || '';
  }});
  applyProviderState(true);
}})();
</script>
"""


@app.route("/services/new", methods=["GET", "POST"])
@login_required
def service_new():
    error = ""
    draft_entry = None
    draft_secret = None
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        provider = (request.form.get("provider") or "dynu").strip().lower()
        hostnames = normalize_hostnames(request.form.get("hostnames") or request.form.get("hostname") or "")
        hostname = hostnames[0] if hostnames else ""
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        draft_entry = {
            "id": "",
            "name": name,
            "enabled": request.form.get("enabled") == "on",
            "provider": provider,
            "ip_mode": (request.form.get("ip_mode") or "ipv4").strip().lower(),
            "hostname": hostname,
            "hostnames": hostnames,
        }
        draft_secret = {"username": username, "password": ""}
        spec = PROVIDER_SPECS.get(provider)
        if not spec:
            error = "Provider aktuell nicht unterstützt."
        elif not name or not hostnames:
            error = t("fill_all_fields")
        elif spec["require_username"] and not username:
            error = spec["create_error"]
        elif not password:
            error = spec["create_error"]
        else:
            data = load_entries()
            entry_id = secrets.token_hex(8)
            data["entries"].append(
                {
                    "id": entry_id,
                    "name": name,
                    "enabled": request.form.get("enabled") == "on",
                    "provider": provider,
                    "ip_mode": (request.form.get("ip_mode") or "ipv4").strip().lower(),
                    "hostname": hostname,
                    "hostnames": hostnames,
                    "created_at": now_iso(),
                    "updated_at": now_iso(),
                }
            )
            save_entries(data)
            set_entry_secret(entry_id, username if spec["show_username"] else "", password)
            write_audit_log(f"service created: {', '.join(hostnames)}")
            return redirect(url_for("services"), code=303)
    return layout(service_form(entry=draft_entry, error=error, secret_override=draft_secret), active="services")


@app.route("/services/<entry_id>/edit", methods=["GET", "POST"])
@login_required
def service_edit(entry_id: str):
    current = find_entry(entry_id)
    if not current:
        return redirect(url_for("services"), code=303)
    error = ""
    form_entry = current
    form_secret = None
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        provider = (request.form.get("provider") or "dynu").strip().lower()
        hostnames = normalize_hostnames(request.form.get("hostnames") or request.form.get("hostname") or "")
        hostname = hostnames[0] if hostnames else ""
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        form_entry = {
            "id": entry_id,
            "name": name,
            "enabled": request.form.get("enabled") == "on",
            "provider": provider,
            "ip_mode": (request.form.get("ip_mode") or "ipv4").strip().lower(),
            "hostname": hostname,
            "hostnames": hostnames,
        }
        form_secret = {"username": username, "password": ""}
        spec = PROVIDER_SPECS.get(provider)
        if not spec:
            error = "Provider aktuell nicht unterstützt."
        elif not name or not hostnames:
            error = t("fill_all_fields")
        elif spec["require_username"] and not username:
            error = spec["update_error"]
        else:
            secret = get_entry_secret(entry_id)
            next_password = password if password else secret.get("password", "")
            next_username = username if spec["show_username"] else ""
            if not next_password:
                error = spec["update_error"]
            else:
                data = load_entries()
                for entry in data["entries"]:
                    if entry["id"] != entry_id:
                        continue
                    entry["name"] = name
                    entry["provider"] = provider
                    entry["ip_mode"] = (request.form.get("ip_mode") or "ipv4").strip().lower()
                    entry["hostname"] = hostname
                    entry["hostnames"] = hostnames
                    entry["enabled"] = request.form.get("enabled") == "on"
                    entry["updated_at"] = now_iso()
                save_entries(data)
                set_entry_secret(entry_id, next_username, next_password)
                write_audit_log(f"service updated: {', '.join(hostnames)}")
                return redirect(url_for("services"), code=303)
    return layout(service_form(entry=form_entry, error=error, secret_override=form_secret), active="services")


@app.route("/services/toggle", methods=["POST"])
@login_required
def services_toggle():
    entry_id = (request.form.get("entry_id") or "").strip()
    data = load_entries()
    for entry in data["entries"]:
        if entry["id"] == entry_id:
            entry["enabled"] = not bool(entry.get("enabled", True))
            entry["updated_at"] = now_iso()
            write_audit_log(f"service toggled: {', '.join(entry_hostnames(entry))} -> {entry['enabled']}")
            break
    save_entries(data)
    if request.headers.get("X-Requested-With") == "fetch":
        return ("", 204)
    return redirect(url_for("services"), code=303)


@app.route("/services/delete", methods=["POST"])
@login_required
def services_delete():
    entry_id = (request.form.get("entry_id") or "").strip()
    data = load_entries()
    before = len(data["entries"])
    data["entries"] = [entry for entry in data["entries"] if entry["id"] != entry_id]
    if len(data["entries"]) != before:
        delete_entry_secret(entry_id)
        status = load_status()
        status["entries"].pop(entry_id, None)
        save_status(status)
        save_entries(data)
        write_audit_log(f"service deleted: {entry_id}")
    return redirect(url_for("services"), code=303)


@app.route("/services/run", methods=["POST"])
@login_required
def services_run():
    entry_id = (request.form.get("entry_id") or "").strip()
    return_to = (request.form.get("return_to") or "").strip()
    ok, output = run_panel_update(force=True, entry_id=entry_id)
    entry = find_entry(entry_id)
    label = ", ".join(entry_hostnames(entry)) if entry else entry_id
    write_audit_log(f"manual service update run: {label} {'ok' if ok else 'error'}")
    if request.headers.get("X-Requested-With") == "fetch":
        return jsonify({"ok": ok, "output": output[:400], "entry_id": entry_id})
    if return_to == "/":
        return redirect(url_for("index"), code=303)
    return redirect(url_for("services", notice=output[:400], level="ok" if ok else "error"), code=303)


@app.route("/setup-config", methods=["GET", "POST"])
@login_required
def setup_config():
    data = load_setup()
    message = ""
    if request.method == "POST":
        data = save_setup(
            {
                "interval_minutes": int(request.form.get("interval_minutes") or 5),
                "boot_delay_seconds": int(request.form.get("boot_delay_seconds") or 120),
                "request_timeout_seconds": int(request.form.get("request_timeout_seconds") or 5),
                "retry_count": int(request.form.get("retry_count") or 2),
                "retry_delay_seconds": int(request.form.get("retry_delay_seconds") or 3),
                "only_update_on_change": request.form.get("only_update_on_change") == "on",
                "log_lines": int(request.form.get("log_lines") or 40),
                "ipv4_sources": [line.strip() for line in (request.form.get("ipv4_sources") or "").splitlines() if line.strip()],
                "ipv6_sources": [line.strip() for line in (request.form.get("ipv6_sources") or "").splitlines() if line.strip()],
                "mdns_enabled": request.form.get("mdns_enabled") == "on",
                "mdns_hostname": (request.form.get("mdns_hostname") or "ddns.local").strip(),
                "local_proxy_enabled": request.form.get("local_proxy_enabled") == "on",
            }
        )
        sync_timer_unit(data)
        sync_local_access(data)
        write_audit_log("global setup updated")
        message = t("setup_saved")
    ipv4_sources_text = "\n".join(data["ipv4_sources"])
    ipv6_sources_text = "\n".join(data["ipv6_sources"])
    body = f"""
<h1>{html.escape(t("setup"))}</h1>
<div class="card form-card">
<form method="post" class="form-grid">
<div><label>{html.escape(t("interval_minutes"))}</label><input type="number" min="1" name="interval_minutes" value="{data['interval_minutes']}" required></div>
<div><label>{html.escape(t("boot_delay_seconds"))}</label><input type="number" min="5" name="boot_delay_seconds" value="{data['boot_delay_seconds']}" required></div>
<div><label>{html.escape(t("request_timeout_seconds"))}</label><input type="number" min="2" name="request_timeout_seconds" value="{data['request_timeout_seconds']}" required></div>
<div><label>{html.escape(t("retry_count"))}</label><input type="number" min="0" name="retry_count" value="{data['retry_count']}" required></div>
<div><label>{html.escape(t("retry_delay_seconds"))}</label><input type="number" min="1" name="retry_delay_seconds" value="{data['retry_delay_seconds']}" required></div>
<div><label>{html.escape(t("audit_log_lines"))}</label><input type="number" min="10" name="log_lines" value="{data['log_lines']}" required></div>
<div><label>{html.escape(t("ipv4_sources"))}</label><textarea class="config-textarea" name="ipv4_sources">{html.escape(ipv4_sources_text)}</textarea></div>
<div><label>{html.escape(t("ipv6_sources"))}</label><textarea class="config-textarea" name="ipv6_sources">{html.escape(ipv6_sources_text)}</textarea></div>
<div><label>{html.escape(t("mdns_hostname"))}</label><input type="text" name="mdns_hostname" value="{html.escape(data['mdns_hostname'])}" required></div>
<label><input type="checkbox" name="only_update_on_change" {"checked" if data['only_update_on_change'] else ""}> {html.escape(t("only_update_on_change"))}</label>
<label><input type="checkbox" name="mdns_enabled" {"checked" if data['mdns_enabled'] else ""}> {html.escape(t("mdns_enabled"))}</label>
<label><input type="checkbox" name="local_proxy_enabled" {"checked" if data['local_proxy_enabled'] else ""}> {html.escape(t("local_proxy_enabled", hostname=data['mdns_hostname']))}</label>
<div class="actions-row">
<button class="primary" type="submit">{html.escape(t("save"))}</button>
<a class="btn secondary" href="/">{html.escape(t("back"))}</a>
</div>
{"<p>" + html.escape(message) + "</p>" if message else ""}
</form>
</div>
"""
    return layout(body, active="setup-config")


BASE = """
<!DOCTYPE html>
<html lang="{{ locale }}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DDNS Panel</title>
{% if branding.favicon_url %}
<link rel="icon" type="image/png" sizes="512x512" href="{{ branding.favicon_url }}">
<link rel="shortcut icon" href="/favicon.ico">
<link rel="apple-touch-icon" href="{{ branding.favicon_url }}">
{% endif %}
<style>
:root{
  --space-1:8px;
  --space-2:16px;
  --space-3:26px;
  --space-4:40px;
  --radius:4px;
  --bg:#070b12;
  --bg-elev:#0b1320;
  --bg-panel:#0f1827;
  --card:#0e1725;
  --card-2:#121e30;
  --text:#eaf3ff;
  --text-muted:#7f93ad;
  --border:#22324a;
  --border-strong:#34506f;
  --primary:#2de0ff;
  --primary-2:#10b8d9;
  --secondary:#162235;
  --success:#2dd4a3;
  --warning:#ffb020;
  --danger:#ff5d73;
  --shadow:0 20px 60px rgba(0,0,0,.38);
  --glow:0 0 0 1px rgba(45,224,255,.12), 0 0 24px rgba(45,224,255,.08);
}
*{box-sizing:border-box;}
html,body{
  margin:0;
  padding:0;
  color:var(--text);
  font-family:"Segoe UI",Arial,sans-serif;
  line-height:1.45;
  background:
    linear-gradient(180deg, rgba(6,9,16,.72) 0%, rgba(9,17,27,.78) 35%, rgba(5,8,14,.84) 100%),
    {% if branding.background_url %}url('{{ branding.background_url }}'),{% endif %}
    radial-gradient(circle at top left, rgba(45,224,255,.08), transparent 28%),
    radial-gradient(circle at top right, rgba(89,102,255,.10), transparent 24%),
    linear-gradient(180deg, #060910 0%, #09111b 35%, #05080e 100%);
  background-position:center center, center center, top left, top right, center center;
  background-repeat:no-repeat, no-repeat, no-repeat, no-repeat, no-repeat;
  background-size:cover, cover, auto, auto, auto;
  background-attachment:fixed, fixed, scroll, scroll, scroll;
}
body::before{
  content:"";
  position:fixed;
  inset:0;
  pointer-events:none;
  opacity:.35;
  background-image:
    linear-gradient(rgba(64,93,130,.10) 1px, transparent 1px),
    linear-gradient(90deg, rgba(64,93,130,.08) 1px, transparent 1px);
  background-size:32px 32px;
  mask-image:linear-gradient(180deg, rgba(0,0,0,.72), transparent 92%);
}
.brand-mark{
  display:block;
  width:auto;
}
.brand-mark-topbar{
  width:min(240px, 42vw);
  max-width:240px;
  max-height:none;
  transform:scale(1.08);
  transform-origin:left center;
  margin-right:12px;
  margin-top:0;
  filter:drop-shadow(0 8px 22px rgba(45,224,255,.16));
}
.topbar{
  position:sticky;
  top:0;
  z-index:20;
  display:flex;
  justify-content:space-between;
  gap:var(--space-2);
  align-items:center;
  padding:18px var(--space-3);
  background:linear-gradient(180deg, rgba(8,14,24,.94), rgba(10,17,28,.88));
  border-bottom:1px solid var(--border-strong);
  backdrop-filter:blur(12px);
  box-shadow:0 12px 30px rgba(0,0,0,.32);
}
.topbar > div:first-child{
  position:relative;
  padding-left:18px;
  min-height:58px;
  display:flex;
  align-items:center;
  overflow:visible;
}
.topbar > div:first-child::before{
  content:"";
  position:absolute;
  left:0;
  top:6px;
  width:8px;
  height:38px;
  background:linear-gradient(180deg, var(--primary), #86f6ff);
  clip-path:polygon(0 0, 100% 0, 100% 76%, 58% 100%, 0 100%);
  box-shadow:0 0 18px rgba(45,224,255,.45);
}
.topbar h1{
  margin:0;
  font-size:2.25rem;
  font-family:"Trebuchet MS","Arial Narrow",Arial,sans-serif;
  font-weight:700;
  letter-spacing:.22em;
  text-transform:uppercase;
  color:#ecfbff;
  text-shadow:0 0 18px rgba(45,224,255,.18), 0 12px 30px rgba(0,0,0,.34);
}
.topbar-brand-fallback{
  margin:0;
}
.app-shell{
  min-height:100vh;
}
.container{
  position:relative;
  padding:var(--space-3);
  display:grid;
  gap:var(--space-2);
}
.card{
  position:relative;
  overflow:hidden;
  background:linear-gradient(180deg, rgba(15,24,39,.94), rgba(11,19,32,.96));
  border:1px solid var(--border);
  border-radius:var(--radius);
  padding:var(--space-2);
  box-shadow:var(--shadow);
}
.form-card{
  width:min(100%, 1040px);
  margin:0 auto;
}
.card::before{
  content:"";
  position:absolute;
  inset:0 auto auto 0;
  width:96px;
  height:2px;
  background:linear-gradient(90deg, var(--primary), transparent);
}
.card::after{
  content:"";
  position:absolute;
  right:0;
  top:0;
  width:28px;
  height:28px;
  border-top:1px solid rgba(45,224,255,.35);
  border-right:1px solid rgba(45,224,255,.35);
}
.page-head{display:flex;justify-content:space-between;gap:var(--space-2);align-items:flex-start;}
.page-head h1{
  margin:0;
  font-size:1.4rem;
  letter-spacing:.06em;
  text-transform:uppercase;
}
.muted{color:var(--text-muted);}
.nav-chip{
  display:inline-flex;
  align-items:center;
  min-height:36px;
  padding:0 14px;
  border:1px solid rgba(234,243,255,.18);
  border-radius:999px;
  background:rgba(255,255,255,.05);
  color:#dce8f5;
  text-transform:uppercase;
  letter-spacing:.12em;
  font-size:.78rem;
}
.sr-only{
  position:absolute;
  width:1px;
  height:1px;
  padding:0;
  margin:-1px;
  overflow:hidden;
  clip:rect(0,0,0,0);
  border:0;
}
.language-form{
  display:inline-flex;
  align-items:center;
}
.language-menu{
  position:relative;
  display:inline-flex;
}
.language-menu-toggle{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  gap:8px;
  min-height:34px;
  min-width:86px;
  padding:6px 10px;
  border:1px solid var(--border-strong);
  border-radius:3px;
  background:linear-gradient(180deg, #152235, #101a29);
  color:var(--text);
  cursor:pointer;
  font-size:.78rem;
  letter-spacing:.06em;
  text-transform:uppercase;
  list-style:none;
}
.language-menu-toggle:hover{
  border-color:var(--primary);
  box-shadow:var(--glow);
  transform:translateY(-1px);
}
.language-menu[open] .language-menu-toggle{
  border-color:var(--primary);
  box-shadow:var(--glow);
}
.language-menu-list{
  position:absolute;
  top:calc(100% + 8px);
  right:0;
  z-index:30;
  display:grid;
  gap:6px;
  min-width:96px;
  padding:10px;
  border:1px solid var(--border-strong);
  border-radius:3px;
  background:linear-gradient(180deg, rgba(15,24,39,.98), rgba(11,19,32,.98));
  box-shadow:0 18px 36px rgba(0,0,0,.42);
}
.language-menu-item{
  width:100%;
  min-height:34px;
  padding:0 10px;
  justify-content:flex-start;
  gap:8px;
  font-size:.78rem;
}
.language-menu-item.active{
  background:linear-gradient(180deg, rgba(45,224,255,.22), rgba(45,224,255,.10));
  border-color:var(--primary);
  color:#f4fdff;
  font-weight:700;
  box-shadow:var(--glow);
}
.flag-badge{
  display:inline-block;
  width:18px;
  height:12px;
  border-radius:2px;
  border:1px solid rgba(255,255,255,.18);
  box-shadow:inset 0 0 0 1px rgba(255,255,255,.06);
  flex:0 0 auto;
}
.flag-image{
  object-fit:cover;
  overflow:hidden;
}
.language-form select{
  min-width:132px;
  min-height:36px;
  padding:8px 10px;
  font-size:.82rem;
}
details summary{
  list-style:none;
  cursor:pointer;
  user-select:none;
  font-size:1rem;
  letter-spacing:.05em;
  text-transform:uppercase;
}
details summary::-webkit-details-marker{display:none;}
table{
  width:100%;
  border-collapse:separate;
  border-spacing:0;
}
th,td{
  text-align:left;
  padding:13px 12px;
  border-bottom:1px solid rgba(44,65,93,.74);
  vertical-align:top;
}
th{
  color:var(--text-muted);
  font-size:.82rem;
  letter-spacing:.08em;
  text-transform:uppercase;
  background:rgba(255,255,255,.02);
}
tr:hover td{background:rgba(255,255,255,.018);}
input,select,textarea{
  width:100%;
  min-height:42px;
  padding:10px 12px;
  border-radius:3px;
  border:1px solid var(--border);
  background:linear-gradient(180deg, #09111b, #0d1624);
  color:var(--text);
  box-shadow:inset 0 0 0 1px rgba(255,255,255,.015);
}
select option{
  color:var(--text);
  background:#0d1624;
}
input:focus,select:focus,textarea:focus{
  outline:none;
  border-color:var(--primary);
  box-shadow:var(--glow);
}
input[type="checkbox"]{
  width:18px;
  min-height:18px;
  height:18px;
  accent-color:var(--primary);
}
button,.btn{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-height:40px;
  padding:0 14px;
  border-radius:3px;
  border:1px solid var(--border-strong);
  background:linear-gradient(180deg, #152235, #101a29);
  color:var(--text);
  text-decoration:none;
  cursor:pointer;
  text-transform:uppercase;
  letter-spacing:.06em;
  font-size:.84rem;
  transition:.16s ease;
}
button:hover,.btn:hover{
  border-color:var(--primary);
  box-shadow:var(--glow);
  transform:translateY(-1px);
}
.primary{background:var(--primary);border-color:var(--primary);color:#fff;}
.primary:hover{
  background:var(--primary-2);
  color:#03121b;
}
.btn.secondary.active{
  background:linear-gradient(180deg, rgba(45,224,255,.22), rgba(45,224,255,.10));
  border-color:var(--primary);
  color:#f4fdff;
  font-weight:700;
  box-shadow:var(--glow);
}
.delete{
  border-color:rgba(255,93,115,.38);
  background:linear-gradient(180deg, rgba(80,20,30,.9), rgba(54,14,22,.95));
}
.badge{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-width:86px;
  min-height:30px;
  padding:0 10px;
  border-radius:2px;
  border:1px solid var(--border-strong);
  font-size:.82rem;
  font-weight:700;
  letter-spacing:.08em;
  text-transform:uppercase;
}
.badge.online{
  background:linear-gradient(180deg, rgba(45,212,163,.18), rgba(45,212,163,.08));
  border-color:rgba(45,212,163,.45);
  color:#96f4d5;
}
.badge.offline{
  background:linear-gradient(180deg, rgba(255,93,115,.17), rgba(255,93,115,.08));
  border-color:rgba(255,93,115,.40);
  color:#ffb7c1;
}
.notice{
  padding:12px 14px;
  border-radius:3px;
  border:1px solid var(--border-strong);
}
.notice.ok{
  background:linear-gradient(180deg, rgba(45,212,163,.12), rgba(45,212,163,.06));
  border-color:rgba(45,212,163,.30);
}
.notice.warn,.warn{
  background:linear-gradient(180deg, rgba(255,176,32,.14), rgba(255,176,32,.07));
  border-color:rgba(255,176,32,.28);
}
.form-grid{display:grid;gap:var(--space-2);}
.actions-row{display:flex;gap:var(--space-1);flex-wrap:wrap;align-items:center;}
.table-actions{display:flex;gap:var(--space-1);flex-wrap:wrap;align-items:center;}
.table-actions form{display:inline-flex;margin:0;}
.table-actions-cell{white-space:nowrap;}
.table-footer-actions{display:flex;justify-content:flex-end;margin-top:16px;}
.kv-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:var(--space-2);}
.kv{
  display:grid;
  gap:6px;
  padding:14px;
  border-radius:3px;
  background:linear-gradient(180deg, rgba(18,30,48,.95), rgba(11,19,32,.95));
  border:1px solid var(--border);
  box-shadow:inset 0 0 0 1px rgba(255,255,255,.02);
}
.kv-label{
  color:var(--text-muted);
  font-size:.78rem;
  letter-spacing:.08em;
  text-transform:uppercase;
}
.host-badge{display:inline-flex;align-items:center;min-height:32px;padding:0 12px;border-radius:999px;background:rgba(79,140,255,.16);border:1px solid rgba(79,140,255,.30);}
.config-textarea{min-height:170px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}
pre{white-space:pre-wrap;word-break:break-word;}
footer{
  padding:0 var(--space-3) var(--space-4) var(--space-3);
  color:var(--text-muted);
  font-size:.82rem;
  letter-spacing:.12em;
  text-transform:uppercase;
  text-align:center;
}
.page-login{
  overflow:hidden;
}
.page-login .app-shell{
  filter:blur(16px) saturate(.68) brightness(.72);
  transform:scale(1.015);
  transform-origin:center top;
  pointer-events:none;
  user-select:none;
}
.page-login .topbar,
.page-login .container,
.page-login footer{
  opacity:.82;
}
.page-login::after{
  content:"";
  position:fixed;
  inset:0;
  background:
    linear-gradient(180deg, rgba(4,8,14,.22), rgba(4,8,14,.62)),
    radial-gradient(circle at 20% 10%, rgba(255,255,255,.10), transparent 24%);
  pointer-events:none;
}
.login-overlay{
  position:fixed;
  inset:0;
  z-index:50;
  display:grid;
  place-items:center;
  padding:24px;
}
.login-dialog{
  width:min(100%, 460px);
  padding:28px;
  border:1px solid rgba(173,231,255,.24);
  background:
    linear-gradient(180deg, rgba(20,31,48,.90), rgba(10,18,30,.94)),
    rgba(255,255,255,.04);
  backdrop-filter:blur(18px) saturate(1.15);
  box-shadow:
    0 24px 80px rgba(0,0,0,.50),
    0 0 0 1px rgba(255,255,255,.04),
    0 0 48px rgba(45,224,255,.10);
}
.login-toolbar{
  display:flex;
  justify-content:flex-end;
  margin:0 0 8px 0;
}
.login-brand{
  display:flex;
  justify-content:center;
  align-items:center;
  margin:-6px 0 12px 0;
  min-height:220px;
}
.login-logo{
  display:block;
  width:min(100%, 320px);
  max-width:320px;
  height:auto;
  filter:drop-shadow(0 12px 28px rgba(45,224,255,.18));
}
.login-signature{
  display:block;
  width:min(100%, 160px);
  max-width:160px;
  height:auto;
  filter:drop-shadow(0 8px 18px rgba(45,224,255,.14));
}
.login-signature-wrap{
  display:flex;
  align-items:center;
  justify-content:center;
  margin:-14px auto 14px auto;
}
.login-preview-head{
  min-height:78px;
}
.footer-signature{
  display:inline-flex;
  align-items:center;
  gap:8px;
  min-height:72px;
  overflow:visible;
}
.footer-signature img{
  display:block;
  max-height:60px;
  width:auto;
  transform:none;
  margin-right:0;
  filter:drop-shadow(0 8px 18px rgba(45,224,255,.14));
}
@media (max-width: 800px){
  .topbar,.page-head{flex-direction:column;}
  th,td{padding:10px 8px;}
  .topbar h1{font-size:1.65rem;letter-spacing:.14em;}
  .container{padding:18px;}
  .login-dialog{padding:22px 18px;}
  .page-login .app-shell{filter:blur(12px) saturate(.68) brightness(.74);}
  .brand-mark-topbar{
    width:min(220px, 62vw);
    transform:scale(1.04);
    margin-right:8px;
  }
  .login-brand{min-height:180px;}
  .login-logo{width:min(100%, 260px);}
  .login-signature{width:min(100%, 128px);}
  .login-signature-wrap{margin:-10px auto 12px auto;gap:6px;}
  .footer-signature{min-height:56px;}
  .footer-signature img{
    max-height:44px;
  }
}
</style>
</head>
<body class="{{ page_class }}">
  <div class="app-shell">
    <div class="topbar">
      <div>
        {% if branding.site_logo_url %}
        <img class="brand-mark brand-mark-topbar" src="{{ branding.site_logo_url }}" alt="DDNS Panel">
        {% else %}
        <h1 class="topbar-brand-fallback">DDNS Panel</h1>
        {% endif %}
      </div>
      <div class="actions-row">{{ nav|safe }}</div>
    </div>
    <main class="container">{{ body|safe }}</main>
    <footer>
      {% if branding.signature_url %}
      <span class="footer-signature"><img src="{{ branding.signature_url }}" alt="Signatur"></span>
      {% else %}
      DDNS Panel
      {% endif %}
    </footer>
  </div>
  {{ overlay|safe }}
  <script>
    document.querySelectorAll('form[data-async-toggle="1"]').forEach((form) => {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const checkbox = form.querySelector('input[type="checkbox"]');
        const previous = checkbox ? checkbox.checked : null;
        try {
          const response = await fetch(form.action, {
            method: 'POST',
            body: new FormData(form),
            headers: {'X-Requested-With': 'fetch'}
          });
          if (!response.ok) {
            throw new Error('toggle failed');
          }
        } catch (error) {
          if (checkbox) {
            checkbox.checked = !previous;
          }
        }
      });
    });
    document.querySelectorAll('form[data-async-run="1"]').forEach((form) => {
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const button = form.querySelector('button');
        const previousLabel = button ? button.textContent : '';
        if (button) {
          button.disabled = true;
          button.textContent = 'Läuft...';
        }
        try {
          const response = await fetch(form.action, {
            method: 'POST',
            body: new FormData(form),
            headers: {'X-Requested-With': 'fetch'}
          });
          if (!response.ok) {
            throw new Error('run failed');
          }
          window.location.reload();
        } catch (error) {
          if (button) {
            button.disabled = false;
            button.textContent = previousLabel;
          }
        }
      });
    });
  </script>
</body>
</html>
"""


ensure_runtime_layout()
app.secret_key = load_or_create_secret_key()
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=REMEMBER_ME_DAYS)
init_auth_defaults()


if __name__ == "__main__":
    sync_local_access(load_setup())
    status = load_status()
    status["local_ip"] = get_primary_lan_ip()
    save_status(status)
    app.run(host="0.0.0.0", port=PANEL_PORT)
