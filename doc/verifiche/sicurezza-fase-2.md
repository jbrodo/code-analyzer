# Verifiche di sicurezza della Fase 2

## S-05 — Feed e mirror

Revisione di progetto in sola lettura, 2026-11-16, su ADR-0024 e ADR-0006 e sui fatti di V-05 (`scanner-fase-2.md`). Il codice dei feed EPSS e KEV non esiste ancora (E-01..E-06): nulla è stato eseguito, e ogni voce è una richiesta per quei task o per un ADR. S-06 ricontrolla l'implementazione.

Esito: nessun critico, 1 alto, 7 medi, 5 bassi. L'alto non ferma E-01..E-04: va risolto in ADR-0021 prima che il livello da punteggio diventi attivo (X-06, X-08). **La decisione sul rischio residuo spetta all'utente.**

### Cosa regge

- La sincronizzazione non riceve il workspace e scarica file interi: nessun dato del repository raggiunge la rete, nemmeno l'elenco delle CVE.
- L'origine non si cambia da `.code-analyzer.yml`.
- Uno snapshot che fallisce un controllo si scarta per intero; il puntatore cambia solo dopo la validazione.
- I campi di testo di KEV non entrano nel report, quindi non arrivano alla UI né ai commenti delle PR.
- Il feed assente è distinto dalla CVE non valutata, e il report registra SHA-256 e identità del contenuto: un punteggio si può ricostruire e contestare.
- Il mirror fallisce chiuso senza firma valida.

### Alto

**S5-A1. Dopo il Gate 2 il gate dipende da feed senza firma, e l'errore è nel verso sbagliato.**
Oggi i livelli delle dipendenze vengono dal CVSS (ADR-0009) e i due feed non toccano il gate. Con il livello da punteggio P moltiplica tutto: un EPSS portato a zero, o una voce tolta da KEV, porta P al minimo di §6.1 (0,01) e una vulnerabilità con CVSS massimo scende a `basso`. Chi riesce a servire uno snapshot plausibile ma alterato, o un mirror compromesso, spegne il gate per tutte le dipendenze senza toccare il repository. Il verso opposto (voce aggiunta a KEV) blocca le pipeline: rumoroso, ma sicuro.
ADR-0024 delimita l'effetto a "cambia l'ordinamento e può cambiare un livello": è corretto per singolo finding, ma l'attacco vale per tutti insieme.
Richiesta per ADR-0021 (A-06), una delle tre:

1. un limite inferiore al livello di una dipendenza in funzione del CVSS, in configurazione, così i feed possono alzare un livello ma non azzerarlo;
2. con origine `public`, livello attivo uguale al più grave tra quello da punteggio e quello provvisorio di ADR-0009, per le sole dipendenze;
3. accettazione esplicita del rischio da parte dell'utente, scritta nell'ADR.

**Decisione dell'utente del 2026-11-16: richiesta 1.** A-06 scrive in ADR-0021 il limite inferiore dal CVSS, con i valori nella configurazione di scoring e un caso nella tabella di regressione (F-05).

Fino al Gate 2 vale D2-10: il gate non legge i punteggi, e l'effetto è limitato all'ordinamento usato in G2.b, dove lo snapshot è registrato e il confronto si può rifare.

### Medi

| ID | Problema | Richiesta | Dove |
| --- | --- | --- | --- |
| S5-M1 | **Ritorno a uno snapshot vecchio.** I controlli non guardano la data del contenuto: un file autentico ma vecchio di mesi supera forma, dimensione e conteggio. Nasconde le voci di KEV aggiunte nel frattempo | Rifiutare uno snapshot con `score_date` o `catalogVersion` precedente a quello in cache. Avviso `feeds-stale` anche quando il contenuto appena scaricato è più vecchio della soglia di età | E-02, E-03; emendamento di ADR-0024 |
| S5-M2 | **La plausibilità guarda solo il numero di voci.** Si possono alterare migliaia di punteggi senza cambiare il conteggio | KEV: una voce presente nello snapshot precedente e assente nel nuovo è anomala, perché il catalogo cresce. Avviso con il numero, rifiuto oltre una soglia piccola in configurazione. EPSS: rifiuto se la quota di CVE con variazione oltre una soglia supera un tetto, entrambi in configurazione e tarati sugli snapshot di F-04 | E-02, E-03 |
| S5-M3 | **Senza cache ogni sincronizzazione è la prima.** Su un runner effimero senza cache dei feed non esiste uno snapshot precedente: S5-M1 e S5-M2 non scattano mai e resta solo il conteggio minimo | Il report dice se lo snapshot è stato confrontato con uno precedente. La documentazione dell'Action indica la cache dei feed come requisito di sicurezza, non solo di velocità | E-06, N-04, L-05 |
| S5-M4 | **Feed assente e P.** Il valore di P senza EPSS è una costante ancora da fissare. Se è basso, impedire lo scaricamento (rete bloccata, `--offline` senza cache) abbassa tutti i punteggi: stesso verso di S5-A1 | P senza feed non inferiore al valore di una CVE con EPSS medio; e ADR-0021 decide se, con il livello da punteggio attivo, `enrichment-feed-missing` fa uscire `gate` con 2 come una scansione parziale | A-06 |
| S5-M5 | **Lettura nel processo della CLI.** A differenza dei database dei plugin, questi file si leggono sull'host con i permessi dell'utente. Il JSON di KEV ha un tetto di 32 MiB a fronte di 1,85 MB reali; in Fase 1 un JSON di 23 MiB ha portato a 586 MiB di memoria (M-10) | Tetto di KEV a 8 MiB. Limiti su profondità e numero di elementi con il lettore difensivo già usato per i SARIF. Tetto alla lunghezza di riga del CSV. `RecursionError` e `MemoryError` trattati come snapshot respinto | E-02, E-03 |
| S5-M6 | **Chiave del mirror.** ADR-0024 riusa la verifica di ADR-0005 senza dire con quale chiave si firma. Il job che costruisce il mirror ha la rete e legge dati non fidati: se firma con la chiave delle immagini, comprometterlo espone la firma dei plugin | Chiave dei feed distinta da quella delle immagini, con ancora di fiducia propria nel pacchetto | E-05; emendamento di ADR-0024 |
| S5-M7 | **Mirror firmato ma vecchio.** La firma prova l'origine, non la freschezza: un artefatto firmato mesi fa resta valido | L'indice firmato porta la data di costruzione e le identità dei contenuti. Valgono S5-M1 e una età massima dell'indice, in configurazione | E-05 |

### Bassi

- **S5-B1. Redirect.** ADR-0024 li ammette verso l'host dell'origine. Aggiungere: solo HTTPS a ogni passo, numero massimo di passi, nessuna credenziale inoltrata.
- **S5-B2. Richieste in uscita.** Indirizzi fissi senza parametri, intestazioni fisse, `User-Agent` senza nome dell'host, dell'utente o del repository. Un test con la rete simulata controlla che `--offline` non apra connessioni e che nessuna richiesta contenga dati del workspace.
- **S5-B3. Origine nel report.** L'origine è un'etichetta. Per un'origine diversa da `public` e dal mirror verificato, il report porta anche l'host, senza credenziali, e `gate` lo stampa tra gli avvisi: chi rivede una pipeline deve vedere da dove arrivano i dati che ordinano i finding.
- **S5-B4. Valori ammessi.** `knownRansomwareCampaignUse` si accetta solo tra i valori noti; `dateAdded` solo come data; l'identificativo della CVE con un modello stretto. La colonna `percentile` di EPSS si valida anche se non si usa.
- **S5-B5. Rilettura dalla cache.** Lo snapshot in cache si ricontrolla al caricamento: SHA-256 rispetto al puntatore e stessi controlli di forma. È la voce B-05 della Fase 1, qui più rilevante perché il file si legge sull'host.

### Effetto di un EPSS manipolato sul punteggio

Variante A, §6.1, per una dipendenza: P vale 1,0 se la CVE è in KEV, altrimenti il massimo tra EPSS e 0,01.

| Manipolazione | Effetto su P | Effetto oggi (D2-10) | Effetto con il livello da punteggio |
| --- | --- | --- | --- |
| EPSS abbassato o riga tolta | Fino a 0,01 | Ordinamento in ombra | Il livello scende fino a `basso`: S5-A1 |
| Voce tolta da KEV | Da 1,0 al valore di EPSS | Ordinamento in ombra | Cade l'override "in KEV e raggiungibile" di §6.3: S5-A1 |
| EPSS alzato | Fino a 1,0 | Ordinamento in ombra | Livello più alto: pipeline bloccate, visibile |
| Voce aggiunta a KEV | 1,0 | Ordinamento in ombra | Override a `critico`: pipeline bloccate, visibile |
| Feed reso irraggiungibile | Costante di ADR-0021 | Avviso | S5-M4 |

Gli altri fattori non cambiano e nessuna manipolazione esegue codice. Con più CVE sullo stesso finding si usa il massimo: per abbassare P vanno alterate tutte.

### Rischio che resta

Con origine `public` un file plausibile, recente e coerente con il precedente, ma alterato in poche righe, non si riconosce: le fonti non firmano. S5-M1 e S5-M2 alzano il costo, non lo eliminano. Lo chiude solo una fonte firmata, cioè il mirror di D2-05 costruito da una rete fidata, oppure la richiesta 1 o 2 di S5-A1, che toglie al feed il potere di abbassare un livello.
