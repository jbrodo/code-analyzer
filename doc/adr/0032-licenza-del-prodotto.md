# ADR-0032: Licenza del prodotto

- Stato: Accettato il 2026-11-27 dall'utente
- Data: 2026-11-27
- Decisione umana richiesta: sì (licenza del prodotto), presa il 2026-11-27
- Riferimenti: `LICENSE`, `README.md`; ADR-0013, 0015, 0027; D-0015, D2-14

## Contesto

Dal 2026-11-09 il codice del progetto aveva una licenza copyleft che consente a chiunque di venderlo e non ammette l'aggiunta di un divieto. L'utente vuole che **le aziende lo possano usare gratuitamente, ma che terzi non lo possano vendere**, mantenendo per sé la possibilità di farlo. All'ultima verifica la cronologia aveva un solo autore umano, il titolare, oltre agli aggiornamenti automatici delle dipendenze.

## Decisione

Il codice del progetto è distribuito con la **licenza di Apache, versione 2.0, con la condizione aggiuntiva Commons Clause 1.0**. Licenziante: Riccardo Roveda.

- **Condizione:** il testo è quello pubblicato su `commonsclause.com`; ogni sua riga è stata confrontata con la pagina il 2026-11-27. Sono compilati i tre campi finali.
- **Licenza di base:** è la copia integrale distribuita con il sistema operativo.
- **Metadati:** nei pacchetti Python il campo `license` usa un riferimento personalizzato (`LicenseRef-…`), perché la combinazione non ha un identificatore standard.

## Opzioni scartate

- **Mantenere la licenza precedente:** non permette di vietare la vendita.
- **PolyForm Shield:** il suo limite riguarda i prodotti concorrenti, anche gratuiti, e non la vendita in sé.
- **PolyForm Noncommercial:** vieta anche l'uso gratuito da parte delle aziende.
- **Business Source License, Functional Source License:** i limiti scadono.

## Conseguenze

- Il progetto è **source-available, non open source**, e la documentazione non lo presenta come open source. Gli scanner orchestrati restano con le loro licenze.
- **Non è retroattivo.** Le versioni già pubblicate, in un repository pubblico, restano utilizzabili secondo la licenza di allora, anche per la vendita.
- Chi modifica il programma **non è obbligato a pubblicare** le modifiche.
- La definizione di vendita usa «del tutto o in gran parte», che lascia margini di interpretazione. Le risposte frequenti sul sito della clausola la presentano come più stretta di quanto il testo possa far pensare, per esempio su consulenza e prodotti costruiti sopra il programma: fa fede il testo di `LICENSE`, e il punto va chiarito con un legale.
- **Contributi di terzi:** perché il titolare possa vendere anche quelli serve un accordo scritto con chi contribuisce. Non c'è ancora.
- **Da rivalutare prima di distribuire:** D-0015 e le valutazioni di D2-14 presupponevano la licenza precedente. In particolare l'argomento usato per l'immagine di `hadolint` (stessa famiglia di licenza del prodotto, `doc/verifiche/scanner-fase-2.md`) non vale più, e va verificato che nessun componente con copyleft formi con il codice del progetto un'unica opera.
- **Auto-analisi:** la policy classifica `ignota` (livello `medio`) una licenza che non riconosce, e il gate fallisce da `alto` in su. Le eccezioni approvate per le dichiarazioni della licenza precedente possono non corrispondere più a nessun finding: toglierle spetta a chi le ha approvate.
- **Non è un parere legale.** Prima di contare sul divieto vanno verificati con un legale: la tutela delle parti scritte con strumenti di intelligenza artificiale, usati ampiamente nel progetto; eventuali diritti di datori di lavoro o committenti; l'adeguatezza del testo allo scopo.
