import React, { useRef } from 'react'
import { cva } from 'class-variance-authority'
import {
  motion,
  useMotionValue,
  useSpring,
  useTransform,
} from 'motion/react'
import { cn } from '@/lib/utils'

const DEFAULT_SIZE = 36
const DEFAULT_MAGNIFICATION = 46
const DEFAULT_DISTANCE = 140
const DEFAULT_DISABLEMAGNIFICATION = false

const dockVariants = cva(
  'floating-toolbar'
)

const Dock = React.forwardRef(
  (
    {
      className,
      children,
      iconSize = DEFAULT_SIZE,
      iconMagnification = DEFAULT_MAGNIFICATION,
      disableMagnification = DEFAULT_DISABLEMAGNIFICATION,
      iconDistance = DEFAULT_DISTANCE,
      direction = 'middle',
      ...props
    },
    ref
  ) => {
    const mouseX = useMotionValue(Infinity)

    const renderChildren = () => {
      return React.Children.map(children, (child) => {
        if (React.isValidElement(child) && (child.type === DockIcon || child.type?.displayName === 'DockIcon')) {
          return React.cloneElement(child, {
            ...child.props,
            mouseX,
            size: child.props.size ?? iconSize,
            magnification: child.props.magnification ?? iconMagnification,
            disableMagnification: child.props.disableMagnification ?? disableMagnification,
            distance: child.props.distance ?? iconDistance,
          })
        }
        return child
      })
    }

    return (
      <motion.div
        ref={ref}
        onMouseMove={(e) => mouseX.set(e.pageX)}
        onMouseLeave={() => mouseX.set(Infinity)}
        {...props}
        className={cn(dockVariants(), className, {
          'items-start': direction === 'top',
          'items-center': direction === 'middle',
          'items-end': direction === 'bottom',
        })}
      >
        {renderChildren()}
      </motion.div>
    )
  }
)

Dock.displayName = 'Dock'

const DockIcon = React.forwardRef(
  (
    {
      size = DEFAULT_SIZE,
      magnification = DEFAULT_MAGNIFICATION,
      disableMagnification,
      distance = DEFAULT_DISTANCE,
      mouseX,
      className,
      children,
      style,
      ...props
    },
    forwardedRef
  ) => {
    const internalRef = useRef(null)
    const ref = forwardedRef || internalRef
    const defaultMouseX = useMotionValue(Infinity)

    const distanceCalc = useTransform(mouseX ?? defaultMouseX, (val) => {
      const bounds = ref.current?.getBoundingClientRect() ?? { x: 0, width: 0 }
      return val - bounds.x - bounds.width / 2
    })

    const targetRatio = disableMagnification ? 1 : magnification / size
    const scaleTransform = useTransform(
      distanceCalc,
      [-distance, 0, distance],
      [1, targetRatio, 1]
    )

    const scale = useSpring(scaleTransform, {
      mass: 0.1,
      stiffness: 150,
      damping: 12,
    })

    return (
      <motion.div
        ref={ref}
        style={{
          scale,
          transformOrigin: 'center center',
          ...style,
        }}
        className={cn('dock-icon-wrapper', className)}
        {...props}
      >
        {children}
      </motion.div>
    )
  }
)

DockIcon.displayName = 'DockIcon'

export { Dock, DockIcon, dockVariants }
