/*
    DEEPDRIVE FORENSIC YARA RULESET
    Автор: MachinistX
    Дата: 22.02.2026
    Описание: Комплексный набор правил для поиска цифровых следов в RAW-дампах.
*/

rule Forensic_Messengers
{
    meta:
        description = "Следы популярных и защищенных мессенджеров (Telegram, Discord, WhatsApp, Signal, Tox и др.)"
        category = "Communications"

    strings:
        // Telegram
        $tg_1 = "t.me/" nocase ascii wide
        $tg_2 = "telegram.me/" nocase ascii wide
        $tg_3 = "telegram.org/" nocase ascii wide
        $tg_4 = "tg://resolve?domain=" nocase ascii wide

        // Discord
        $discord_1 = "discord.gg/" nocase ascii wide
        $discord_2 = "discordapp.com/api" nocase ascii wide
        $discord_3 = "discord.com/channels/" nocase ascii wide
        $discord_4 = "cdn.discordapp.com/attachments/" nocase ascii wide

        // WhatsApp 
        $wa_1 = "wa.me/" nocase ascii wide
        $wa_2 = "chat.whatsapp.com/" nocase ascii wide
        $signal_1 = "signal.group/#" nocase ascii wide
        $signal_2 = "sgnl://" nocase ascii wide

        $tox_1 = "tox:" nocase ascii wide
        $tox_2 = "qTox" nocase ascii wide
        $session_1 = "getsession.org" nocase ascii wide
        $threema_1 = "threema.id/" nocase ascii wide
        $xmpp_1 = "xmpp:" nocase ascii wide

    condition:
        any of them
}

rule Forensic_Cloud_and_Sharing
{
    meta:
        description = "Ссылки на облачные хранилища, файлообменники и сервисы заметок"
        category = "Data Exfiltration"

    strings:
        $mega_1 = "mega.nz/file/" nocase ascii wide
        $mega_2 = "mega.nz/folder/" nocase ascii wide
        $mega_3 = "mega.co.nz" nocase ascii wide
        $gdrive_1 = "drive.google.com/file/d/" nocase ascii wide
        $gdrive_2 = "drive.google.com/drive/folders/" nocase ascii wide
        $dropbox_1 = "dropbox.com/s/" nocase ascii wide
        $dropbox_2 = "dl.dropboxusercontent.com" nocase ascii wide
        $yandex_1 = "disk.yandex.ru/d/" nocase ascii wide
        $mailru_1 = "cloud.mail.ru/public/" nocase ascii wide

        $pastebin_1 = "pastebin.com/" nocase ascii wide
        $privnote_1 = "privnote.com/" nocase ascii wide
        $anonfiles_1 = "anonfiles.com/" nocase ascii wide
        $gofile_1 = "gofile.io/d/" nocase ascii wide
        $sendspace_1 = "sendspace.com/file/" nocase ascii wide
        $controlc_1 = "controlc.com/" nocase ascii wide
        $ghostbin_1 = "ghostbin.co/paste/" nocase ascii wide

    condition:
        any of them
}

rule Forensic_DarkWeb_Tor_I2P
{
    meta:
        description = "Поиск ссылок на скрытые сети (Tor Onion, I2P, Freenet)"
        category = "Darknet"

    strings:

        $onion_v3 = /[a-z2-7]{56}\.onion/ nocase ascii wide
        $onion_v2 = /[a-z2-7]{16}\.onion/ nocase ascii wide
        $tor_gateway = ".onion.ws" nocase ascii wide
        $tor_gateway2 = ".onion.ly" nocase ascii wide
        $tor_browser = "Tor Browser" ascii wide

        // I2P
        $i2p_1 = ".i2p" nocase ascii wide
        $i2p_2 = "http://127.0.0.1:7657" nocase ascii wide // Стандартный порт роутера I2P

    condition:
        any of them
}

rule Forensic_Crypto_Artifacts
{
    meta:
        description = "Следы криптовалютных кошельков, бирж и миксеров"
        category = "Finance"

    strings:
        $bc_1 = "blockchain.info/tx/" nocase ascii wide
        $bc_2 = "blockchair.com/" nocase ascii wide
        $bc_3 = "etherscan.io/address/" nocase ascii wide
        $bc_4 = "tronscan.org/#/address/" nocase ascii wide
        $bc_5 = "xmrchain.net/tx/" nocase ascii wide

        $ex_1 = "binance.com" nocase ascii wide
        $ex_2 = "coinbase.com" nocase ascii wide
        $ex_3 = "kraken.com" nocase ascii wide
        $ex_4 = "localmonero.co" nocase ascii wide
        $ex_5 = "bestchange.ru" nocase ascii wide

        $uri_1 = "bitcoin:" nocase ascii wide
        $uri_2 = "ethereum:" nocase ascii wide
        $uri_3 = "monero:" nocase ascii wide
        $uri_4 = "litecoin:" nocase ascii wide
        $uri_5 = "tron:" nocase ascii wide

        $wallet_1 = "Electrum" ascii wide
        $wallet_2 = "Exodus" ascii wide
        $wallet_3 = "MetaMask" nocase ascii wide
        $wallet_4 = "Trust Wallet" nocase ascii wide

    condition:
        any of them
}

rule Forensic_Suspicious_Infra
{
    meta:
        description = "Индикаторы туннелей, Dynamic DNS и хакерской инфраструктуры"
        category = "Infrastructure"

    strings:
        $ngrok_1 = ".ngrok.io" nocase ascii wide
        $ngrok_2 = ".ngrok-free.app" nocase ascii wide
        $localtunnel = ".loca.lt" nocase ascii wide
        $serveo = "serveo.net" nocase ascii wide

        // DDNS
        $ddns_1 = ".duckdns.org" nocase ascii wide
        $ddns_2 = ".no-ip.com" nocase ascii wide
        $ddns_3 = ".no-ip.org" nocase ascii wide
        $ddns_4 = ".ddns.net" nocase ascii wide
        $ddns_5 = ".hopto.org" nocase ascii wide

    condition:
        any of them
}
