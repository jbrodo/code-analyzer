"use strict";
// Le fasce dentro un gruppo. Funzioni pure: `tiers` è { numero: fascia }, con 0 (assente) per i
// finding non spostati, negativo per chi viene prima di loro e positivo per chi viene dopo.
// Si sposta solo il finding scelto: gli altri restano fra loro come erano.
const Bands = (() => {
  const tierOf = (tiers, n) => tiers[n] ?? 0;

  function bandsOf(members, tiers) {
    const values = [...new Set(members.map((n) => tierOf(tiers, n)))].sort((a, b) => a - b);
    return values.map((tier) => ({
      tier,
      ids: members.filter((n) => tierOf(tiers, n) === tier).sort((a, b) => a - b),
    }));
  }

  // Rinumera 1, 2, … da una parte e -1, -2, … dall'altra; lo 0 resta 0.
  function compact(members, tiers) {
    const values = [...new Set(members.map((n) => tierOf(tiers, n)))].sort((a, b) => a - b);
    const below = values.filter((v) => v < 0), above = values.filter((v) => v > 0);
    const next = new Map([[0, 0]]);
    below.forEach((v, i) => next.set(v, i - below.length));
    above.forEach((v, i) => next.set(v, i + 1));
    const out = { ...tiers };
    for (const n of members) {
      const value = next.get(tierOf(tiers, n));
      if (value) out[n] = value; else delete out[n];
    }
    return out;
  }

  function target(members, tiers, n, action) {
    const bands = bandsOf(members, tiers);
    const at = bands.findIndex((band) => band.ids.includes(n));
    const tier = bands[at].tier, alone = bands[at].ids.length === 1;
    const others = members.filter((x) => x !== n).map((x) => tierOf(tiers, x));
    if (action === "reset") return 0;
    if (action === "top") return alone && at === 0 ? tier : Math.min(0, ...others) - 1;
    if (action === "bottom") return alone && at === bands.length - 1 ? tier : Math.max(0, ...others) + 1;
    const step = action === "up" ? -1 : 1;
    if (!alone) return tier + step / 2; // esce dalla fascia condivisa, subito sopra o sotto
    return bands[at + step]?.tier ?? tier; // da solo: si unisce alla fascia vicina
  }

  function move(members, tiers, n, action) {
    return compact(members, { ...tiers, [n]: target(members, tiers, n, action) });
  }

  const shape = (members, tiers) => JSON.stringify(bandsOf(members, tiers).map((band) => band.ids));

  const canMove = (members, tiers, n, action) =>
    members.length > 1 && shape(members, move(members, tiers, n, action)) !== shape(members, tiers);

  return { bandsOf, move, canMove };
})();
if (typeof module !== "undefined") module.exports = Bands;
