import { useEffect, useRef } from 'react'
import { modals } from './modalStack'

/** Register a modal layer while `active`, and run `onEscape` for an Escape
 *  pressed while this layer is the top one (see modalStack). Returns a ref
 *  holding the layer id (0 while inactive), set before any key can arrive,
 *  for handlers of other keys that must also act only on top. */
export function useModalLayer(active: boolean, onEscape?: () => void) {
  const onEscapeRef = useRef(onEscape)
  onEscapeRef.current = onEscape
  const idRef = useRef(0)

  useEffect(() => {
    if (!active) return
    const id = modals.push()
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
  }, [active])

  return idRef
}
