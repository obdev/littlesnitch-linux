// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2026 Objective Development Software GmbH

// Minimal service worker — required for PWA installability.
// No fetch handler: all requests pass through to the network unchanged,
// ensuring resources are always loaded fresh from the server.

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
