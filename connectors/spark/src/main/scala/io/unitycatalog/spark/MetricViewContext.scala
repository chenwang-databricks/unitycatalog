package io.unitycatalog.spark

/**
 * Thread-local holder for metric view context during source table resolution.
 *
 * When UCProxy.loadTable() encounters a METRIC_VIEW, it sets the view's table ID here.
 * When the Spark analyzer subsequently resolves the metric view's source table (another
 * loadTable() call), UCProxy reads this context and passes the view ID as the `dependent`
 * parameter in the credential vending request, enabling view-mediated authorization.
 */
object MetricViewContext {
  private val viewId = new ThreadLocal[String]()

  def set(id: String): Unit = viewId.set(id)

  def get(): Option[String] = Option(viewId.get())

  def clear(): Unit = viewId.remove()
}
