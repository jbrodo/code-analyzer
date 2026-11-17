# Livelli, punteggi e varianti

**Stato: i punteggi non sono ancora calcolati.** Questa pagina dice cosa cambia, quando, e cosa c'è oggi. Decisioni: ADR-0009 (livelli provvisori), ADR-0018 (le due varianti), D2-10. L'ADR sulla formula dei punteggi (ADR-0021) non è ancora scritto.

## Cosa c'è oggi

I livelli (`critico`, `alto`, `medio`, `basso`) sono ancora **quelli provvisori della Fase 1**: derivano dalla severità dello scanner e dalle policy (per esempio le licenze), senza punteggio né raggiungibilità. Una vulnerabilità non raggiungibile con CVSS alto blocca comunque. Il campo `level_source` dice da dove viene il livello di ogni finding.

Nei contratti ci sono già, e restano vuoti:

- `variant_scores`: i punteggi in ombra delle varianti A e B, ciascuno con i propri fattori e la loro evidenza;
- `level_source` con i valori `score` e `override`, per quando il livello verrà dal punteggio;
- le sezioni `scoring` e `service` di `.code-analyzer.yml` (`scoring.variant`, `service.tier`, `service.internet_facing`, `service.catalog_id`): si validano, ma **non hanno effetto**, e il report le elenca tra le sezioni inerti.

**Non esistono** l'opzione `--variant` né i punteggi in `json`, `sarif` o `table`.

## Cosa cambierà e quando

La decisione D2-10 è che **fino al Gate 2 il gate resta sui livelli provvisori**: le CI dei repository esistenti non cambiano esito prima che l'ordinamento dei punteggi sia validato. Intanto A e B si calcolano entrambe in ombra e si registrano nel report. Dopo la scelta della variante predefinita il livello da punteggio diventa attivo, **una volta sola**, e molti finding cambieranno livello (ADR-0009): alcuni salgono, altri scendono. Quel passaggio sarà annunciato qui e nelle note di rilascio; chi ha un `block_on` o un'eccezione legata a un livello dovrà rivederli.

## Limiti già noti del punteggio

- **«Segreto valido esposto» non si applica.** Provare un segreto contro il servizio che lo ha emesso richiede rete, che i plugin non hanno (ADR-0006, ADR-0012): ogni segreto ha `evidence.validity` `unverified` e non può essere forzato a critico per validità.
- **Criticità ed esposizione sono dichiarate, non verificate.** Senza un server il tier e l'esposizione del servizio vengono dal blocco `service` del repository (o da un file generato dalla pipeline): chi modifica il branch può cambiarli. Il report lo dirà con l'avviso `service-from-repository`; in una PR vale il valore del branch base, quindi una PR non può abbassarli per sé. Con un server vale il catalogo (ADR-0028).
- Le definizioni operative dei fattori di raggiungibilità e di churn non sono ancora scritte.

## Nuovi tipi di finding

I plugin della Fase 2 aggiungono finding di qualità, IaC, test e architettura, tutti con livelli provvisori: vedi la tabella dei plugin nel `README.md`.
