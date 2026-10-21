// Greywatch shield mark, shared by the landing and dashboard navigation so the
// brand is defined once. Decorative by default (aria-hidden); pass a `title`
// and it becomes a labelled image instead.

export function GreywatchMark({ size = 24, title, className, ...props }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : 'true'}
      aria-label={title}
      className={className}
      {...props}
    >
      <path
        d="M16 2.5 27 7v9.2c0 6.3-4.4 10.9-11 13.3C9.4 27.1 5 22.5 5 16.2V7L16 2.5Z"
        fill="#0E1512"
        stroke="#34d399"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <circle cx="16" cy="16" r="3" fill="#a3e635" />
    </svg>
  )
}

export default GreywatchMark
