// createMultiSelection — shared multi-selection manager used by the Rules and
// Blocklist-entries sections.
//
// Config:
//   getCount()          → number   — length of the current item list
//   getItemByIndex(i)   → item     — item at index i; may return undefined for
//                                    unloaded virtual-list pages
//   getId(item)         → id       — extract the selection key from an item
//   onChanged()                    — called after every mutation; the caller is
//                                    responsible for refreshing the DOM
//
// Returned object:
//   handleClick(event, index, id)  — process a mouse click with modifiers
//   navigate(delta, options)       — keyboard navigation; options: { extend? }
//                                    returns the next index (number) or false
//   has(id)             → boolean
//   getAll()            → Set      — a copy of the current selection
//   size                → number   (getter)
//   clear()
//   setSelected(ids, anchorIndex)  — replace selection; anchorIndex defaults
//                                    to null (also resets cursor to same value)


window.FooterApp = {
    createMultiSelection: function(config) {
        let ids = new Set();
        // anchorIndex: the fixed end of a shift-selection range (set on click or
        //              plain-arrow navigation; stays put during shift-arrow extend).
        // cursorIndex: the moving end of the range (updated on every navigation).
        let anchorIndex = null;
        let cursorIndex = null;

        function selectedIndices() {
            const count = config.getCount();
            const result = [];
            for(let i = 0; i < count; i += 1) {
                const item = config.getItemByIndex(i);
                if(item && ids.has(config.getId(item))) {
                    result.push(i);
                }
            }
            return result;
        }

        return {
            handleClick(event, index, id) {
                if(event.shiftKey && anchorIndex !== null) {
                    const start = Math.min(anchorIndex, index);
                    const end = Math.max(anchorIndex, index);
                    if(!event.ctrlKey && !event.metaKey) {
                        ids.clear();
                    }
                    for(let i = start; i <= end; i += 1) {
                        const item = config.getItemByIndex(i);
                        if(item) { // item may be undefined for unloaded virtual-list pages
                            ids.add(config.getId(item));
                        }
                    }
                    cursorIndex = index;
                    // anchorIndex stays fixed
                } else if(event.ctrlKey || event.metaKey) {
                    if(ids.has(id)) {
                        ids.delete(id);
                    } else {
                        ids.add(id);
                    }
                    anchorIndex = index;
                    cursorIndex = index;
                } else {
                    ids.clear();
                    ids.add(id);
                    anchorIndex = index;
                    cursorIndex = index;
                }
                config.onChanged();
            },

            navigate(delta, options = {}) {
                if(delta !== 1 && delta !== -1) {
                    return false;
                }
                const count = config.getCount();
                if(count === 0) {
                    return false;
                }

                const extend = options.extend === true;

                // Use cursorIndex as the starting position. If it is unset or out of
                // range, fall back to the last/first selected item depending on direction.
                let current = cursorIndex;
                if(current === null || current < 0 || current >= count) {
                    const selIndices = selectedIndices();
                    if(selIndices.length > 0) {
                        current = delta > 0 ? selIndices[selIndices.length - 1] : selIndices[0];
                    } else {
                        current = delta > 0 ? -1 : count;
                    }
                }

                const nextIndex = Math.max(0, Math.min(count - 1, current + delta));
                const nextItem = config.getItemByIndex(nextIndex);
                if(!nextItem) {
                    return false;
                }

                if(extend) {
                    // Anchor is fixed; pin it now if not yet set.
                    if(anchorIndex === null || anchorIndex < 0 || anchorIndex >= count) {
                        anchorIndex = Math.max(0, Math.min(count - 1, current));
                    }
                    const start = Math.min(anchorIndex, nextIndex);
                    const end = Math.max(anchorIndex, nextIndex);
                    ids.clear();
                    for(let i = start; i <= end; i += 1) {
                        const item = config.getItemByIndex(i);
                        if(item) { // item may be undefined for unloaded virtual-list pages
                            ids.add(config.getId(item));
                        }
                    }
                    cursorIndex = nextIndex;
                    // anchorIndex stays fixed
                } else {
                    ids.clear();
                    ids.add(config.getId(nextItem));
                    anchorIndex = nextIndex;
                    cursorIndex = nextIndex;
                }

                config.onChanged();
                return nextIndex;
            },

            has(id) {
                return ids.has(id);
            },

            getAll() {
                return new Set(ids);
            },

            get size() {
                return ids.size;
            },

            clear() {
                ids.clear();
                anchorIndex = null;
                cursorIndex = null;
                config.onChanged();
            },

            setSelected(newIds, newAnchorIndex = null) {
                ids = new Set(newIds);
                anchorIndex = newAnchorIndex;
                cursorIndex = newAnchorIndex;
                config.onChanged();
            },
        };
    }
}