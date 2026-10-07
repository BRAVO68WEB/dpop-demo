import type { ReactNode } from 'react'

export function Shell({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="page">
      <header className="top">
        <div>
          <p className="kicker">LoginRadius</p>
          <p className="product">DPoP demo</p>
        </div>
        {action}
      </header>
      <main className="stack">{children}</main>
    </div>
  )
}

export function Card({
  title,
  heading = 'h2',
  children,
}: {
  title: string
  heading?: 'h1' | 'h2'
  children: ReactNode
}) {
  const Title = heading
  return (
    <section className="card">
      <Title>{title}</Title>
      {children}
    </section>
  )
}
