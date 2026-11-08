# ADR-0004: Esecuzione dei plugin e livelli di isolamento

- Stato: Accettato il 2026-11-08 dall'utente; rischio residuo da valutare con `security` (S-01)
- Data: 2026-11-08
- Decisione umana richiesta: sì (accettare un isolamento inferiore a gVisor in CI e in locale)
- Riferimenti: §2, §7.1, §7.2, §15; lacuna 8

## Contesto

§2 e §7 prevedono plugin in immagini firmate con gVisor o Firecracker. §2 chiede anche una CLI unica per CI, server e locale, dove quel runtime di norma manca: i runner CI ospitati e Docker Desktop non hanno `runsc`. Sulla macchina di sviluppo attuale Docker è presente, `runsc` e Podman no.

"Immagine CLI unica" e "`image` per plugin" (§7.1) sono in tensione: non è detto se gli scanner stiano dentro l'immagine CLI.

## Opzioni

1. **Immagine unica con tutti gli scanner, eseguiti come sottoprocessi.** Non serve Docker e funziona ovunque, ma cade la rete `none` per plugin, il file system è condiviso con la CLI e la firma non è per plugin. Contraddice §7.2.
2. **Solo gVisor/Firecracker.** Rispetta §2, ma la CLI non gira sulla maggior parte delle CI e in locale.
3. **Un'immagine per plugin, runtime OCI scelto a run time, con livello di isolamento dichiarato.**
4. **Come 3, con ripiego su sottoprocesso sull'host.** Massima portabilità, ma il codice analizzato viene elaborato senza confinamento.

## Raccomandazione

Opzione 3.

- Una sola forma di esecuzione: immagine per plugin (§7.1). "CLI unica" significa un solo codice e una sola immagine CLI, che orchestra le immagini dei plugin ma non le contiene.
- Porta `PluginExecutor` (ADR-0002) con adattatore `OciExecutor` per Docker/Podman in Fase 1. L'adattatore Kubernetes con gVisor arriva con il server.
- Livelli registrati nel report per ogni plugin: `gvisor` se `runsc` è registrato nel daemon, altrimenti `hardened-container`.
- `hardened-container` significa: `--network none`, root file system in sola lettura, workspace in sola lettura, `--cap-drop ALL`, `no-new-privileges`, utente non root, limiti di CPU, memoria e PID da `resources` del manifest, profilo seccomp predefinito.
- Il flag `--min-isolation` e il server impongono il livello: su server il minimo è `gvisor` e non è declassabile. Il valore non si legge mai da `.code-analyzer.yml` (ADR-0014).
- Nessun ripiego su sottoprocesso. Senza runtime OCI: exit 2 con messaggio esplicito.
- Firecracker non si implementa finché non serve un requisito che gVisor non copre.

Limiti da far rispettare al confine tra plugin e host:

- `/out` è una directory per plugin, nuova a ogni esecuzione. L'host legge solo file regolari, senza seguire symlink (`O_NOFOLLOW`), e con limite di dimensione.
- I limiti di byte e il loro valore si fissano nel piano misurando le fixture; il loader rifiuta un manifest senza limite.
- Argomenti di container costruiti come lista, senza shell; nessuna variabile d'ambiente dell'host viene passata al plugin.

Modalità di avvio della CLI:

- Installata sull'host: caso di riferimento di Fase 1.
- Da immagine CLI con socket del daemon montato: i plugin sono container fratelli, quindi servono percorsi host (`CA_HOST_WORKSPACE`, `CA_HOST_OUTPUT`). Il socket resta alla sola CLI e non viene mai esposto ai plugin. È un privilegio equivalente a root sull'host e va documentato.

## Conseguenze

- In CI e in locale l'isolamento è inferiore a quello di §2: la difesa è il confinamento del container, senza kernel intermedio. Il rischio residuo è un exploit del parser di uno scanner su contenuto ostile; va valutato dall'agente `security`.
- Le CI senza daemon (es. GitLab su Kubernetes senza DinD) restano non supportate finché non si aggiunge un adattatore; da trattare con il componente GitLab in Fase 2.
- §2 e §7 andranno precisati per dire che gVisor è obbligatorio solo su server.
