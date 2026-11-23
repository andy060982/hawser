import { useEffect, useRef } from 'react'
import { LAYER, modals } from './modalStack'

/** Register a modal layer while `active`, and run `onEscape` for an Escape
 *  pressed while this layer is the top one (see modalStack). Returns a ref
 *  holding the layer id (0 while inactive), set before any key can arrive,
 *  for handlers of other keys that must also act only on top. `priority` is
 *  the layer's z-order tier (modalStack LAYER), matching its CSS z-index. */
export function useModalLayer(active: boolean, onEscape?: () => void, priority: number = LAYER.panel) {
  const onEscapeRef = useRef(onEscape)
  onEscapeRef.current = onEscape
  const idRef = useRef(0)

  useEffect(() => {
    if (!active) return
    const id = modals.push(priority)
    idRef.current = id
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || !modals.isTop(id)) return
      const handler = onEscapeRef.current
      if (!handler) return
      e.preventDefault()
      e.stopPropagation()
      handler()
    }
    window.addEventListener('keydown', onKey, true)
    return () => {
      window.removeEventListener('keydown', onKey, true)
      modals.remove(id)
      if (idRef.current === id) idRef.current = 0
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active])

  return idRef
}
