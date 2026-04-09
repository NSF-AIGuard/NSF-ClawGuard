declare module '*.module.less' {
  const classes: { [key: string]: string }
  export default classes
}

declare module '*.module.css' {
  const classes: { [key: string]: string }
  export default classes
}

declare module '*.less' {
  const content: string
  export default content
}

declare module '*.css' {
  const content: string
  export default content
}

declare module '*.png' {
  const content: string
  export default content
}