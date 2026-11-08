// SPDX-License-Identifier: AGPL-3.0-only
// Utilita' copiata da un progetto terzo: la licenza rende il file soggetto a policy.

module.exports.clamp = (value, low, high) => Math.max(low, Math.min(value, high));
