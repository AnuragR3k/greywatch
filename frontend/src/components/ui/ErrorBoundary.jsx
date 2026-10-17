import { Component } from 'react'
import { ErrorState } from './State'

/** Catches render errors in a subtree so one failing view can't blank the app. */
export class ErrorBoundary extends Component {
  state = { error: null }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    // Surface rather than conceal.
    console.error('[Greywatch] render error:', error, info?.componentStack || '')
  }

  reset = () => this.setState({ error: null })

  render() {
    if (this.state.error) {
      return (
        <div className="p-4">
          <ErrorState
            title="This panel failed to render"
            message={String(this.state.error?.message ?? this.state.error)}
            onRetry={this.reset}
          />
        </div>
      )
    }
    return this.props.children
  }
}
