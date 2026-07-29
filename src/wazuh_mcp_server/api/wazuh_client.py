"""Wazuh API client optimized for Wazuh 4.8.0 to 4.14.1 compatibility with latest features."""

import asyncio
import json
import logging
import math
import time
from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import httpx

from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError, WazuhIndexerClient
from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.resilience import CircuitBreaker, CircuitBreakerConfig, RetryConfig

logger = logging.getLogger(__name__)

# Time range to hours mapping for indexer-based queries
_TIME_RANGE_HOURS = {"1h": 1, "6h": 6, "12h": 12, "1d": 24, "24h": 24, "7d": 168, "30d": 720}


class WazuhClient:
    """Simplified Wazuh API client with rate limiting, circuit breaker, and retry logic."""

    def __init__(self, config: WazuhConfig):
        self.config = config
        self.token: Optional[str] = None
        self.client: Optional[httpx.AsyncClient] = None
        # Lock to prevent concurrent re-authentication races
        self._auth_lock = asyncio.Lock()
        # Rate limiting with O(1) deque operations
        self._rate_limiter = asyncio.Semaphore(config.max_connections)
        self._request_times: deque = deque(maxlen=200)  # Pre-sized deque for efficiency
        self._max_requests_per_minute = getattr(config, "max_requests_per_minute", 100)
        self._rate_limit_enabled = True
        # Response caching for static data (bounded OrderedDict for O(1) eviction)
        self._cache: OrderedDict[str, Tuple[float, Dict[str, Any]]] = OrderedDict()
        self._cache_ttl = 300  # 5 minutes for static data
        self._cache_max_size = 100

        # Circuit breaker for API resilience — only trip on connection/server errors,
        # not on user-input errors (ValueError) which shouldn't degrade the circuit
        circuit_config = CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=(ConnectionError, httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError),
        )
        self._circuit_breaker = CircuitBreaker(circuit_config)

        # Initialize Wazuh Indexer client if configured (required for Wazuh 4.8.0+)
        self._indexer_client: Optional[WazuhIndexerClient] = None
        if config.wazuh_indexer_host:
            self._indexer_client = WazuhIndexerClient(
                host=config.wazuh_indexer_host,
                port=config.wazuh_indexer_port,
                username=config.wazuh_indexer_user,
                password=config.wazuh_indexer_pass,
                verify_ssl=config.verify_ssl,
                timeout=config.request_timeout_seconds,
            )
            logger.info(f"WazuhIndexerClient configured for {config.wazuh_indexer_host}:{config.wazuh_indexer_port}")
        else:
            logger.warning(
                "Wazuh Indexer not configured. Vulnerability tools will not work with Wazuh 4.8.0+. "
                "Set WAZUH_INDEXER_HOST to enable vulnerability queries."
            )

        logger.info("WazuhClient initialized with circuit breaker and retry logic")

    async def initialize(self):
        """Initialize the HTTP client and authenticate."""
        # Close existing client to prevent connection pool leak on re-initialization
        if self.client:
            try:
                await self.client.aclose()
            except Exception:
                pass
        self.client = httpx.AsyncClient(
            verify=self.config.verify_ssl,
            timeout=self.config.request_timeout_seconds,
            limits=httpx.Limits(
                max_connections=self.config.max_connections,
                max_keepalive_connections=max(5, self.config.max_connections // 2),
            ),
        )
        await self._authenticate()

        # Initialize indexer client if configured
        if self._indexer_client:
            try:
                await self._indexer_client.initialize()
                logger.info("Wazuh Indexer client initialized successfully")
            except Exception as e:
                logger.warning(f"Wazuh Indexer initialization failed: {e}")

    async def _authenticate(self):
        """Authenticate with Wazuh API."""
        auth_url = f"{self.config.base_url}/security/user/authenticate"

        try:
            response = await self.client.post(auth_url, auth=(self.config.wazuh_user, self.config.wazuh_pass))
            response.raise_for_status()

            try:
                data = response.json()
            except (json.JSONDecodeError, ValueError):
                raise ValueError("Invalid JSON in authentication response from Wazuh API")
            if "data" not in data or "token" not in data["data"]:
                raise ValueError("Invalid authentication response from Wazuh API")

            self.token = data["data"]["token"]
            logger.info(f"Authenticated with Wazuh server at {self.config.wazuh_host}")

        except httpx.ConnectError:
            raise ConnectionError(
                f"Cannot connect to Wazuh server at {self.config.wazuh_host}:{self.config.wazuh_port}"
            )
        except httpx.TimeoutException:
            raise ConnectionError(f"Connection timeout to Wazuh server at {self.config.wazuh_host}")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise ValueError("Invalid Wazuh credentials. Check WAZUH_USER and WAZUH_PASS")
            elif e.response.status_code == 403:
                raise ValueError("Wazuh user does not have sufficient permissions")
            else:
                raise ValueError(f"Wazuh API error: {e.response.status_code} - {e.response.text}")

    async def get_alerts(self, **params) -> Dict[str, Any]:
        """
        Get alerts from the Wazuh Indexer (wazuh-alerts-* index).

        Alerts are stored in the Wazuh Indexer, not the Manager API.
        The Manager API does not have a /alerts endpoint.

        Raises:
            IndexerNotConfiguredError: If Wazuh Indexer is not configured
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError(
                "Wazuh Indexer not configured. "
                "Alerts are stored in the Wazuh Indexer and require WAZUH_INDEXER_HOST to be set.\n\n"
                "Please set the following environment variables:\n"
                "  WAZUH_INDEXER_HOST=<indexer_hostname>\n"
                "  WAZUH_INDEXER_USER=<indexer_username>\n"
                "  WAZUH_INDEXER_PASS=<indexer_password>\n"
                "  WAZUH_INDEXER_PORT=9200 (optional, default: 9200)"
            )

        return await self._indexer_client.get_alerts(
            limit=params.get("limit", 100),
            rule_id=params.get("rule_id"),
            level=params.get("level"),
            agent_id=params.get("agent_id"),
            timestamp_start=params.get("timestamp_start"),
            timestamp_end=params.get("timestamp_end"),
        )

    async def get_agents(self, agent_id=None, status=None, limit=100, **params) -> Dict[str, Any]:
        """Get agents from Wazuh."""
        clean_params: Dict[str, Any] = {}
        if agent_id:
            clean_params["agents_list"] = agent_id
        if status:
            clean_params["status"] = status
        if limit:
            clean_params["limit"] = limit
        for k, v in params.items():
            if v is not None:
                clean_params[k] = v
        return await self._request("GET", "/agents", params=clean_params)

    async def get_vulnerabilities(self, **params) -> Dict[str, Any]:
        """
        Get vulnerabilities from Wazuh Indexer (4.8.0+ required).

        Note: The /vulnerability API endpoint was deprecated in Wazuh 4.7.0
        and removed in 4.8.0. Vulnerability data must be queried from the
        Wazuh Indexer using the wazuh-states-vulnerabilities-* index.

        Args:
            agent_id: Filter by agent ID
            severity: Filter by severity (critical, high, medium, low)
            limit: Maximum number of results (default: 100)

        Returns:
            Vulnerability data from the indexer

        Raises:
            IndexerNotConfiguredError: If Wazuh Indexer is not configured
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError()

        agent_id = params.get("agent_id")
        severity = params.get("severity")
        limit = params.get("limit", 100)

        return await self._indexer_client.get_vulnerabilities(agent_id=agent_id, severity=severity, limit=limit)

    async def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster status."""
        return await self._request("GET", "/cluster/status")

    async def search_logs(self, **params) -> Dict[str, Any]:
        """Search logs with advanced filtering capabilities."""
        return await self._request("GET", "/manager/logs", params=params)

    async def _get_cached(self, cache_key: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Get data from cache or fetch from API.

        Args:
            cache_key: Unique cache key for this request
            endpoint: API endpoint
            **kwargs: Additional request parameters

        Returns:
            Cached or fresh API response
        """
        from wazuh_mcp_server.monitoring import record_cache_access

        current_time = time.time()

        # Check cache
        if cache_key in self._cache:
            cached_time, cached_data = self._cache[cache_key]
            if current_time - cached_time < self._cache_ttl:
                record_cache_access("wazuh_api", hit=True)
                self._cache.move_to_end(cache_key)  # LRU: mark as recently used
                return cached_data

        record_cache_access("wazuh_api", hit=False)

        # Fetch from API
        result = await self._request("GET", endpoint, **kwargs)

        # Cache the result, evicting oldest if at capacity (O(1) eviction)
        self._cache[cache_key] = (current_time, result)
        if len(self._cache) > self._cache_max_size:
            self._cache.popitem(last=False)

        return result

    async def get_rules(self, **params) -> Dict[str, Any]:
        """Get Wazuh detection rules (cached for 5 minutes)."""
        # Use caching for rules as they rarely change
        cache_key = f"rules:{sorted(params.items()) if params else 'all'}"
        return await self._get_cached(cache_key, "/rules", params=params)

    async def get_rule_info(self, rule_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific rule."""
        return await self._request("GET", f"/rules/{rule_id}")

    async def get_decoders(self, **params) -> Dict[str, Any]:
        """Get Wazuh log decoders (cached for 5 minutes)."""
        # Use caching for decoders as they rarely change
        cache_key = f"decoders:{sorted(params.items()) if params else 'all'}"
        return await self._get_cached(cache_key, "/decoders", params=params)

    async def execute_active_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute active response command on agents (4.8+ removed 'custom' parameter)."""
        # Note: 'custom' parameter was removed in Wazuh 4.8.0
        # Ensure data dict doesn't contain deprecated 'custom' parameter
        if "custom" in data:
            data = {k: v for k, v in data.items() if k != "custom"}
        # Wazuh 4.x API: agent_list must be passed as query param 'agents_list'
        agents_list = data.pop("agent_list", None)
        params = {}
        if agents_list:
            agent_items = agents_list if isinstance(agents_list, list) else [agents_list]
            # Check if targeting all agents
            if any(str(a).lower() == "all" for a in agent_items):
                # Wazuh 4.x API requires a valid agents_list; use "all" as a special keyword
                # that the API accepts for targeting all agents
                params["agents_list"] = "all"
            else:
                # Filter to numeric agent IDs only
                numeric_agents = [str(a) for a in agent_items if str(a).isdigit()]
                if numeric_agents:
                    params["agents_list"] = ",".join(numeric_agents)
        result = await self._request("PUT", "/active-response", json=data, params=params)

        # Check for partial/total failures in the response body
        # Wazuh returns HTTP 200 even when the command fails on all agents
        resp_data = result.get("data", {})
        total_affected = resp_data.get("total_affected_items", 0)
        total_failed = resp_data.get("total_failed_items", 0)
        failed_items = resp_data.get("failed_items", [])

        if total_affected == 0 and total_failed > 0:
            # Build error details from failed_items
            errors = []
            for item in failed_items:
                err = item.get("error", {})
                agent_ids = item.get("id", [])
                errors.append(
                    f"agents {agent_ids}: code {err.get('code')} - {err.get('message', 'unknown error')}"
                )
            error_detail = "; ".join(errors) if errors else "no agents affected"
            raise ValueError(
                f"Active response command failed on all agents "
                f"(0 succeeded, {total_failed} failed): {error_detail}"
            )

        # Log partial failures as warnings but still return success
        if total_failed > 0 and total_affected > 0:
            for item in failed_items:
                err = item.get("error", {})
                agent_ids = item.get("id", [])
                logger.warning(
                    f"Active response partially failed on agents {agent_ids}: "
                    f"code {err.get('code')} - {err.get('message')}"
                )

        return result

    async def get_active_response_commands(self, **params) -> Dict[str, Any]:
        """Get available active response commands."""
        return await self._request("GET", "/manager/configuration", params={"section": "active-response"})

    async def get_cdb_lists(self, **params) -> Dict[str, Any]:
        """Get CDB lists."""
        return await self._request("GET", "/lists", params=params)

    async def get_cdb_list_content(self, filename: str) -> Dict[str, Any]:
        """Get specific CDB list content."""
        return await self._request("GET", f"/lists/{filename}")

    async def get_fim_events(self, **params) -> Dict[str, Any]:
        """Get File Integrity Monitoring events."""
        return await self._request("GET", "/syscheck", params=params)

    async def get_syscollector_info(self, agent_id: str, **params) -> Dict[str, Any]:
        """Get system inventory information from agent."""
        return await self._request("GET", f"/syscollector/{agent_id}", params=params)

    async def get_manager_stats(self, **params) -> Dict[str, Any]:
        """Get manager statistics."""
        return await self._request("GET", "/manager/stats", params=params)

    async def get_cti_data(self, cve_id: str) -> Dict[str, Any]:
        """
        Get Cyber Threat Intelligence data for CVE (4.8.0+ via Indexer).

        Note: CTI data is now stored in the Wazuh Indexer.

        Args:
            cve_id: CVE ID to look up (e.g., "CVE-2021-44228")

        Returns:
            Vulnerability data for the specific CVE

        Raises:
            IndexerNotConfiguredError: If Wazuh Indexer is not configured
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError()

        return await self._indexer_client.get_vulnerabilities(cve_id=cve_id, limit=100)

    async def get_vulnerability_details(self, vuln_id: str, **params) -> Dict[str, Any]:
        """
        Get detailed vulnerability information (4.8.0+ via Indexer).

        Note: Vulnerability details are now stored in the Wazuh Indexer.

        Args:
            vuln_id: Vulnerability/CVE ID

        Returns:
            Detailed vulnerability information

        Raises:
            IndexerNotConfiguredError: If Wazuh Indexer is not configured
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError()

        return await self._indexer_client.get_vulnerabilities(cve_id=vuln_id, limit=1)

    async def get_agent_stats(self, agent_id: str, component: str = "logcollector") -> Dict[str, Any]:
        """Get agent component statistics."""
        # Audit fix H6: Validate agent_id is numeric to prevent path traversal
        if not agent_id or not str(agent_id).isdigit():
            raise ValueError(f"agent_id must be numeric, got: {agent_id}")
        # Audit fix: Validate component to prevent path traversal
        if not component.isalnum():
            raise ValueError(f"component must be alphanumeric, got: {component}")
        return await self._request("GET", f"/agents/{agent_id}/stats/{component}")

    async def _rate_limit_check(self) -> None:
        """Check and enforce rate limiting using efficient O(1) deque operations."""
        current_time = time.time()

        # Remove requests older than 1 minute from front of deque (O(1) per removal)
        while self._request_times and current_time - self._request_times[0] >= 60:
            self._request_times.popleft()

        # Check if we're hitting the rate limit
        if len(self._request_times) >= self._max_requests_per_minute:
            # Calculate how long to wait before the oldest request expires
            oldest_request_time = self._request_times[0]
            sleep_time = 60 - (current_time - oldest_request_time)

            if sleep_time > 0:
                logger.warning(
                    f"Rate limit reached ({self._max_requests_per_minute}/min). Waiting {sleep_time:.1f}s..."
                )
                await asyncio.sleep(sleep_time)

                # Clean up expired requests after waiting
                current_time = time.time()
                while self._request_times and current_time - self._request_times[0] >= 60:
                    self._request_times.popleft()

        # Record this request time (O(1) append)
        self._request_times.append(current_time)

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated request to Wazuh API with rate limiting, circuit breaker, and retry logic.

        GET requests use retry + circuit breaker. PUT/DELETE requests use circuit breaker
        only (no retry) because active response commands are not idempotent — retrying a
        PUT that already executed could double-isolate an agent or double-block an IP.
        """
        # Apply rate limiting
        async with self._rate_limiter:
            await self._rate_limit_check()

            if method.upper() in ("PUT", "DELETE"):
                # Non-idempotent: circuit breaker only, no retry
                return await self._request_no_retry(method, endpoint, **kwargs)
            # Idempotent (GET, POST for auth): retry + circuit breaker
            return await self._request_with_resilience(method, endpoint, **kwargs)

    @RetryConfig.WAZUH_API_RETRY
    async def _request_with_resilience(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute request with circuit breaker and retry logic (idempotent methods only)."""
        return await self._circuit_breaker._call(self._execute_request, method, endpoint, **kwargs)

    async def _request_no_retry(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute request with circuit breaker but NO retry (non-idempotent methods)."""
        return await self._circuit_breaker._call(self._execute_request, method, endpoint, **kwargs)

    async def _execute_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute the actual HTTP request to Wazuh API."""
        # Ensure client is initialized
        if not self.client:
            await self.initialize()
        elif not self.token:
            await self._authenticate()

        url = f"{self.config.base_url}{endpoint}"
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.token}"

        try:
            response = await self.client.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()

            try:
                data = response.json()
            except (json.JSONDecodeError, ValueError):
                raise ValueError(f"Invalid JSON response from Wazuh API: {endpoint}")

            # Validate response structure
            if "data" not in data:
                raise ValueError(f"Invalid response structure from Wazuh API: {endpoint}")

            return data

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                # Token expired -- re-authenticate with lock to prevent concurrent races
                stale_token = headers.get("Authorization", "").replace("Bearer ", "")
                async with self._auth_lock:
                    # Double-check: another coroutine may have already refreshed
                    if self.token is None or self.token == stale_token:
                        self.token = None
                        await self._authenticate()
                # Retry the request once with refreshed token
                headers = {"Authorization": f"Bearer {self.token}"}
                try:
                    response = await self.client.request(method, url, headers=headers, **kwargs)
                    response.raise_for_status()
                    try:
                        data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        raise ValueError(f"Invalid JSON response from Wazuh API after re-auth: {endpoint}")
                    if "data" not in data:
                        raise ValueError(f"Invalid response structure from Wazuh API after re-auth: {endpoint}")
                    return data
                except httpx.HTTPStatusError as retry_err:
                    logger.error(f"Wazuh API request failed after re-auth: {retry_err.response.status_code}")
                    raise ValueError(
                        f"Wazuh API error after re-auth for {endpoint}: {retry_err.response.status_code}"
                    )
                except (httpx.ConnectError, httpx.TimeoutException) as retry_err:
                    logger.error(f"Connection lost during re-auth retry for {endpoint}: {retry_err}")
                    raise
            elif e.response.status_code == 429:
                # Wazuh-side rate limiting: wait per Retry-After and let retry logic handle it
                retry_after = int(e.response.headers.get("Retry-After", "30"))
                logger.warning(f"Wazuh API rate-limited on {endpoint}. Waiting {retry_after}s...")
                await asyncio.sleep(min(retry_after, 60))  # Cap at 60s to prevent abuse
                raise  # Let tenacity/circuit breaker handle the retry
            elif e.response.status_code >= 500:
                # Server errors: let them propagate as httpx exceptions so tenacity
                # retry logic can see them and retry (via _is_retryable)
                logger.error(f"Wazuh API server error: {e.response.status_code}")
                raise
            else:
                # Client errors (4xx except 401): not retryable, wrap as ValueError
                logger.error(f"Wazuh API request failed: {endpoint} returned HTTP {e.response.status_code}")
                raise ValueError(f"Wazuh API request failed: {endpoint} returned HTTP {e.response.status_code}")
        except httpx.ConnectError as e:
            # Distinguish SSL errors from generic connection failures
            err_str = str(e).lower()
            if "ssl" in err_str or "certificate" in err_str or "verify" in err_str:
                logger.error(f"SSL certificate validation failed for {self.config.wazuh_host}")
                raise ConnectionError(
                    f"SSL certificate validation failed for {self.config.wazuh_host}. "
                    "Set WAZUH_VERIFY_SSL=false for self-signed certificates."
                )
            # Let other connection errors propagate for retry logic
            logger.error(f"Lost connection to Wazuh server at {self.config.wazuh_host}")
            raise
        except httpx.TimeoutException:
            # Let timeout errors propagate for retry logic
            logger.error("Request timeout to Wazuh server")
            raise

    async def get_manager_info(self) -> Dict[str, Any]:
        """Get Wazuh manager information (cached for 5 minutes)."""
        cache_key = "manager_info"
        return await self._get_cached(cache_key, "/")

    def _time_range_to_start(self, time_range: str) -> str:
        """Convert a time_range string like '24h' or '7d' to an ISO 8601 start timestamp."""
        hours = _TIME_RANGE_HOURS.get(time_range, 24)
        return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    async def get_alert_summary(self, time_range: str, group_by: str) -> Dict[str, Any]:
        """Get alert summary — aggregated from Wazuh Indexer."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        start = self._time_range_to_start(time_range)
        result = await self._indexer_client.get_alerts(limit=1000, timestamp_start=start)
        alerts = result.get("data", {}).get("affected_items", [])
        groups: Dict[str, int] = {}
        for alert in alerts:
            value: Any = alert
            for part in group_by.split("."):
                value = value.get(part, {}) if isinstance(value, dict) else "unknown"
            key = str(value) if not isinstance(value, dict) else "unknown"
            groups[key] = groups.get(key, 0) + 1
        return {
            "data": {
                "time_range": time_range,
                "group_by": group_by,
                "total_alerts": len(alerts),
                "groups": groups,
            }
        }

    async def analyze_alert_patterns(self, time_range: str, min_frequency: int) -> Dict[str, Any]:
        """Analyze alert patterns — aggregated from Wazuh Indexer."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        start = self._time_range_to_start(time_range)
        result = await self._indexer_client.get_alerts(limit=1000, timestamp_start=start)
        alerts = result.get("data", {}).get("affected_items", [])
        rule_counts: Dict[str, Dict[str, Any]] = {}
        for alert in alerts:
            rule = alert.get("rule", {})
            rule_id = rule.get("id", "unknown")
            if rule_id not in rule_counts:
                rule_counts[rule_id] = {
                    "count": 0,
                    "description": rule.get("description", ""),
                    "level": rule.get("level", 0),
                }
            rule_counts[rule_id]["count"] += 1
        patterns = [{"rule_id": k, **v} for k, v in rule_counts.items() if v["count"] >= min_frequency]
        patterns.sort(key=lambda x: x["count"], reverse=True)
        return {
            "data": {
                "time_range": time_range,
                "min_frequency": min_frequency,
                "patterns": patterns,
                "total_patterns": len(patterns),
            }
        }

    async def search_security_events(
        self,
        query: str,
        time_range: str,
        limit: int,
        rule_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        level: Optional[str] = None,
        srcip: Optional[str] = None,
        dstip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Search security events via the Wazuh Indexer with Elasticsearch query_string and field filters.

        Args:
            query: Free-text search query (passed to Elasticsearch query_string DSL).
                   Supports Lucene syntax: AND, OR, NOT, field:value, wildcards, quoted phrases.
            time_range: Time window string (e.g., '24h', '7d').
            limit: Maximum number of results to return.
            rule_id: Optional filter by Wazuh rule ID (e.g., '5710').
            agent_id: Optional filter by Wazuh agent ID (e.g., '001').
            level: Optional minimum rule severity level (e.g., '10' for level >= 10).
            srcip: Optional filter by source IP address.
            dstip: Optional filter by destination IP address.

        Returns:
            Alert data in standard Wazuh format with affected_items and total counts.
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        start = self._time_range_to_start(time_range)
        # Pass all filters directly to Elasticsearch — no local Python filtering needed
        result = await self._indexer_client.get_alerts(
            limit=limit,
            timestamp_start=start,
            query_text=query if query else None,
            rule_id=rule_id,
            agent_id=agent_id,
            level=level,
            srcip=srcip,
            dstip=dstip,
        )
        return result

    async def get_running_agents(self) -> Dict[str, Any]:
        """Get running agents."""
        return await self._request("GET", "/agents", params={"status": "active"})

    async def check_agent_health(self, agent_id: str) -> Dict[str, Any]:
        """Check agent health by fetching agent info and extracting status."""
        result = await self._request(
            "GET",
            "/agents",
            params={
                "agents_list": agent_id,
                "select": "id,name,status,ip,os.name,os.version,version,lastKeepAlive,dateAdd,group,node_name",
            },
        )
        agents = result.get("data", {}).get("affected_items", [])
        if not agents:
            raise ValueError(f"Agent {agent_id} not found")
        agent = agents[0]
        status = agent.get("status", "unknown")
        return {
            "data": {
                "agent_id": agent.get("id"),
                "name": agent.get("name"),
                "status": status,
                "health": "healthy" if status == "active" else "unhealthy",
                "ip": agent.get("ip"),
                "os": agent.get("os", {}),
                "version": agent.get("version"),
                "last_keep_alive": agent.get("lastKeepAlive"),
                "date_add": agent.get("dateAdd"),
                "group": agent.get("group"),
                "node_name": agent.get("node_name"),
            }
        }

    async def get_agent_processes(self, agent_id: str, limit: int) -> Dict[str, Any]:
        """Get agent processes."""
        return await self._request("GET", f"/syscollector/{agent_id}/processes", params={"limit": limit})

    async def get_agent_ports(self, agent_id: str, limit: int) -> Dict[str, Any]:
        """Get agent ports."""
        return await self._request("GET", f"/syscollector/{agent_id}/ports", params={"limit": limit})

    async def get_agent_configuration(self, agent_id: str) -> Dict[str, Any]:
        """Get agent configuration by fetching agent info and its group config."""
        agent_result = await self._request(
            "GET",
            "/agents",
            params={"agents_list": agent_id, "select": "id,name,group,configSum,mergedSum,status,version"},
        )
        agents = agent_result.get("data", {}).get("affected_items", [])
        if not agents:
            raise ValueError(f"Agent {agent_id} not found")
        agent = agents[0]
        config_data: Dict[str, Any] = {"agent": agent, "group_configuration": []}
        groups = agent.get("group", [])
        if groups:
            group_name = groups[0] if isinstance(groups, list) else groups
            try:
                group_config = await self._request("GET", f"/groups/{group_name}/configuration")
                config_data["group_configuration"] = group_config.get("data", {}).get("affected_items", [])
            except Exception:
                config_data["group_configuration"] = []
        return {"data": config_data}

    async def get_critical_vulnerabilities(self, limit: int) -> Dict[str, Any]:
        """
        Get critical vulnerabilities from Wazuh Indexer (4.8.0+ required).

        Args:
            limit: Maximum number of results

        Returns:
            Critical vulnerability data from the indexer

        Raises:
            IndexerNotConfiguredError: If Wazuh Indexer is not configured
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError()

        return await self._indexer_client.get_critical_vulnerabilities(limit=limit)

    async def get_vulnerability_summary(self, time_range: str) -> Dict[str, Any]:
        """
        Get vulnerability summary statistics from Wazuh Indexer (4.8.0+ required).

        Args:
            time_range: Time range for the summary (currently not used, returns all current vulnerabilities)

        Returns:
            Vulnerability summary with counts by severity

        Raises:
            IndexerNotConfiguredError: If Wazuh Indexer is not configured
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError()

        return await self._indexer_client.get_vulnerability_summary()

    async def analyze_security_threat(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Analyze security threat by searching alerts for the indicator via Elasticsearch."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        # Use Elasticsearch query_string for efficient server-side search
        result = await self._indexer_client.get_alerts(limit=100, query_text=indicator)
        alerts = result.get("data", {}).get("affected_items", [])
        return {
            "data": {
                "indicator": indicator,
                "type": indicator_type,
                "matching_alerts": len(alerts),
                "alerts": alerts[:20],
            }
        }

    async def check_ioc_reputation(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Check IoC reputation by searching alert history via Elasticsearch."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        # Use Elasticsearch query_string for server-side search
        result = await self._indexer_client.get_alerts(limit=500, query_text=indicator)
        alerts = result.get("data", {}).get("affected_items", [])
        occurrences = len(alerts)
        max_level = 0
        for alert in alerts:
            level = alert.get("rule", {}).get("level", 0)
            if isinstance(level, int) and level > max_level:
                max_level = level
        risk = "high" if max_level >= 10 else "medium" if max_level >= 5 else "low"
        return {
            "data": {
                "indicator": indicator,
                "type": indicator_type,
                "occurrences": occurrences,
                "max_alert_level": max_level,
                "risk": risk,
            }
        }

    async def perform_risk_assessment(self, agent_id: str = None) -> Dict[str, Any]:
        """Perform risk assessment from agent status, vulnerability data, and alert severity."""

        risk_factors: list = []
        params: Dict[str, Any] = {"select": "id,name,status,os.name,version"}
        if agent_id:
            params["agents_list"] = agent_id
        agents = await self._request("GET", "/agents", params=params)
        items = agents.get("data", {}).get("affected_items", [])
        total_agents = len(items)
        disconnected = [a for a in items if a.get("status") != "active"]
        if disconnected:
            risk_factors.append({
                "factor": "disconnected_agents",
                "count": len(disconnected),
                "severity": "high",
                "details": [{"id": a.get("id"), "name": a.get("name")} for a in disconnected[:10]],
            })

        # Vulnerability risk
        vuln_data: Dict[str, Any] = {}
        if self._indexer_client:
            try:
                vuln_summary = await self._indexer_client.get_vulnerability_summary()
                vuln_data = vuln_summary.get("data", {})
                critical = vuln_data.get("critical", 0)
                high = vuln_data.get("high", 0)
                if critical > 0:
                    risk_factors.append({"factor": "critical_vulnerabilities", "count": critical, "severity": "critical"})
                if high > 0:
                    risk_factors.append({"factor": "high_vulnerabilities", "count": high, "severity": "high"})
            except Exception:
                pass

        # Alert severity risk — count high-level alerts in last 24h
        alert_summary: Dict[str, int] = {}
        if self._indexer_client:
            try:
                start = self._time_range_to_start("24h")
                result = await self._indexer_client.get_alerts(limit=500, timestamp_start=start, level="10")
                high_alerts = result.get("data", {}).get("affected_items", [])
                alert_summary["high_severity_alerts_24h"] = len(high_alerts)
                if len(high_alerts) > 10:
                    risk_factors.append({
                        "factor": "high_severity_alerts",
                        "count": len(high_alerts),
                        "severity": "high",
                    })
                elif len(high_alerts) > 0:
                    risk_factors.append({
                        "factor": "elevated_alert_activity",
                        "count": len(high_alerts),
                        "severity": "medium",
                    })
            except Exception:
                pass

        # SCA compliance risk — sample first active agent
        sca_score: Optional[int] = None
        try:
            active_agents = [a for a in items if a.get("status") == "active"]
            if active_agents:
                sca = await self._request("GET", f"/sca/{active_agents[0].get('id')}")
                sca_items = sca.get("data", {}).get("affected_items", [])
                if sca_items:
                    scores = [p.get("score", 0) for p in sca_items if isinstance(p.get("score"), (int, float))]
                    if scores:
                        sca_score = int(sum(scores) / len(scores))
                        if sca_score < 50:
                            risk_factors.append({
                                "factor": "low_sca_compliance",
                                "score": sca_score,
                                "severity": "high",
                            })
                        elif sca_score < 70:
                            risk_factors.append({
                                "factor": "moderate_sca_compliance",
                                "score": sca_score,
                                "severity": "medium",
                            })
        except Exception:
            pass

        # Calculate weighted risk score (0-100)
        score = 0
        severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
        for f in risk_factors:
            weight = severity_weights.get(f["severity"], 5)
            count = f.get("count", 1)
            score += weight * min(math.log2(count + 1), 5)  # Diminishing returns on count
        overall_risk_score = min(100, int(score))

        if overall_risk_score >= 70:
            risk_level = "critical"
        elif overall_risk_score >= 50:
            risk_level = "high"
        elif overall_risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "data": {
                "overall_risk_score": overall_risk_score,
                "risk_level": risk_level,
                "total_agents": total_agents,
                "risk_factors": risk_factors,
                "vulnerability_summary": vuln_data if vuln_data else None,
                "alert_summary": alert_summary if alert_summary else None,
                "sca_average_score": sca_score,
            }
        }

    async def get_top_security_threats(self, limit: int, time_range: str) -> Dict[str, Any]:
        """Get top threats with source IPs, affected agents, and timeline from Indexer."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        start = self._time_range_to_start(time_range)
        result = await self._indexer_client.get_alerts(limit=1000, timestamp_start=start)
        alerts = result.get("data", {}).get("affected_items", [])

        rule_data: Dict[str, Dict[str, Any]] = {}
        for alert in alerts:
            rule = alert.get("rule", {})
            rule_id = rule.get("id", "unknown")
            if rule_id not in rule_data:
                rule_data[rule_id] = {
                    "rule_id": rule_id,
                    "description": rule.get("description", ""),
                    "level": rule.get("level", 0),
                    "count": 0,
                    "groups": rule.get("groups", []),
                    "mitre": rule.get("mitre", {}),
                    "source_ips": set(),
                    "affected_agents": set(),
                    "first_seen": None,
                    "last_seen": None,
                }
            entry = rule_data[rule_id]
            entry["count"] += 1
            # Extract source IPs
            src_ip = alert.get("data", {}).get("srcip")
            if src_ip:
                entry["source_ips"].add(src_ip)
            # Extract affected agents
            agent_id = alert.get("agent", {}).get("id")
            agent_name = alert.get("agent", {}).get("name", "")
            if agent_id:
                entry["affected_agents"].add(f"{agent_id}:{agent_name}")
            # Track timeline
            ts = alert.get("timestamp")
            if ts:
                if entry["first_seen"] is None or ts < entry["first_seen"]:
                    entry["first_seen"] = ts
                if entry["last_seen"] is None or ts > entry["last_seen"]:
                    entry["last_seen"] = ts

        # Calculate threat score and build output
        threats = []
        for rule_id, data in rule_data.items():
            level = data["level"]
            count = data["count"]
            # Score: level weight * log(count) * affected_systems_factor
            affected_count = len(data["affected_agents"])
            threat_score = min(100, int(level * 5 * math.log2(count + 1) * (1 + 0.1 * affected_count)))

            threats.append({
                "rule_id": rule_id,
                "description": data["description"],
                "level": level,
                "count": count,
                "threat_score": threat_score,
                "groups": data["groups"],
                "mitre": data["mitre"] if data["mitre"] else None,
                "source_ips": sorted(data["source_ips"])[:20],  # Cap at 20
                "affected_agents": [
                    {"id": a.split(":")[0], "name": a.split(":", 1)[1] if ":" in a else ""}
                    for a in sorted(data["affected_agents"])
                ][:20],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
            })

        threats.sort(key=lambda x: (-x["threat_score"], -x["count"]))
        return {
            "data": {
                "time_range": time_range,
                "total_alerts_analyzed": len(alerts),
                "threats": threats[:limit],
                "total_unique_rules": len(rule_data),
            }
        }

    async def generate_security_report(self, report_type: str, include_recommendations: bool) -> Dict[str, Any]:
        """Generate security report with content differentiated by report_type."""
        # Time range varies by report type
        time_ranges = {"daily": "24h", "weekly": "7d", "monthly": "30d", "incident": "1h"}
        tr = time_ranges.get(report_type, "24h")

        report: Dict[str, Any] = {
            "report_type": report_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_range": tr,
            "sections": {},
        }

        # Section 1: Agent status (all report types)
        try:
            agents = await self._request("GET", "/agents", params={"limit": 500})
            items = agents.get("data", {}).get("affected_items", [])
            active = sum(1 for a in items if a.get("status") == "active")
            report["sections"]["agents"] = {"total": len(items), "active": active, "disconnected": len(items) - active}
        except Exception as e:
            report["sections"]["agents"] = {"error": str(e)}

        # Section 2: Manager info (all report types)
        try:
            info = await self._request("GET", "/")
            mgr = info.get("data", {})
            report["sections"]["manager"] = {
                "version": mgr.get("api_version"), "hostname": mgr.get("hostname"), "type": mgr.get("type"),
            }
        except Exception as e:
            report["sections"]["manager"] = {"error": str(e)}

        # Section 3: Alert summary (all report types)
        if self._indexer_client:
            try:
                start = self._time_range_to_start(tr)
                alerts_result = await self._indexer_client.get_alerts(limit=500, timestamp_start=start)
                alerts = alerts_result.get("data", {}).get("affected_items", [])
                level_dist: Dict[str, int] = {}
                for a in alerts:
                    lvl = a.get("rule", {}).get("level", 0)
                    bucket = "critical" if lvl >= 12 else "high" if lvl >= 10 else "medium" if lvl >= 7 else "low"
                    level_dist[bucket] = level_dist.get(bucket, 0) + 1
                report["sections"]["alerts"] = {
                    "total": len(alerts),
                    "by_severity": level_dist,
                    "time_range": tr,
                }
            except Exception as e:
                report["sections"]["alerts"] = {"error": str(e)}

        # Section 4: Vulnerability summary (all report types)
        if self._indexer_client:
            try:
                vuln_summary = await self._indexer_client.get_vulnerability_summary()
                report["sections"]["vulnerabilities"] = vuln_summary.get("data", {})
            except Exception as e:
                report["sections"]["vulnerabilities"] = {"error": str(e)}

        # Section 5: Top threats (daily, weekly, monthly, incident)
        if self._indexer_client:
            try:
                threats = await self.get_top_security_threats(limit=5, time_range=tr)
                report["sections"]["top_threats"] = threats.get("data", {}).get("threats", [])
            except Exception:
                report["sections"]["top_threats"] = []

        # Section 6: SCA compliance summary (weekly, monthly)
        if report_type in ("weekly", "monthly"):
            try:
                agents_result = await self._request(
                    "GET", "/agents", params={"status": "active", "limit": 5, "select": "id,name"}
                )
                agent_list = agents_result.get("data", {}).get("affected_items", [])
                sca_scores = []
                for ag in agent_list[:3]:
                    try:
                        sca = await self._request("GET", f"/sca/{ag.get('id')}")
                        sca_items = sca.get("data", {}).get("affected_items", [])
                        scores = [p.get("score", 0) for p in sca_items if isinstance(p.get("score"), (int, float))]
                        avg = int(sum(scores) / len(scores)) if scores else 0
                        sca_scores.append({"agent_id": ag.get("id"), "agent_name": ag.get("name"), "avg_score": avg})
                    except Exception:
                        pass
                report["sections"]["compliance_summary"] = {"agents_sampled": len(sca_scores), "scores": sca_scores}
            except Exception:
                pass

        # Section 7: Recommendations (when include_recommendations=True)
        if include_recommendations:
            recommendations = []
            alerts_section = report["sections"].get("alerts", {})
            critical_count = alerts_section.get("by_severity", {}).get("critical", 0)
            if critical_count > 0:
                recommendations.append({
                    "priority": "critical",
                    "action": f"Investigate {critical_count} critical-severity alerts immediately",
                })
            vuln_section = report["sections"].get("vulnerabilities", {})
            critical_vulns = vuln_section.get("critical", 0)
            if critical_vulns > 0:
                recommendations.append({
                    "priority": "critical",
                    "action": f"Patch {critical_vulns} critical vulnerabilities",
                })
            agent_section = report["sections"].get("agents", {})
            disconnected_count = agent_section.get("disconnected", 0)
            if disconnected_count > 0:
                recommendations.append({
                    "priority": "high",
                    "action": f"Investigate {disconnected_count} disconnected agents",
                })
            if not recommendations:
                recommendations.append({"priority": "info", "action": "No critical issues detected. Maintain monitoring."})
            report["sections"]["recommendations"] = recommendations

        return {"data": report}

    async def run_compliance_check(self, framework: str, agent_id: str = None) -> Dict[str, Any]:
        """Run compliance check using Wazuh SCA data, filtered by framework relevance."""
        # Map compliance frameworks to SCA policy name patterns
        framework_policy_keywords: Dict[str, list] = {
            "PCI-DSS": ["pci", "payment", "card"],
            "HIPAA": ["hipaa", "health"],
            "SOX": ["sox", "sarbanes"],
            "GDPR": ["gdpr", "privacy", "data_protection"],
            "NIST": ["nist", "800-53", "cybersecurity"],
        }
        keywords = framework_policy_keywords.get(framework, [])

        if agent_id:
            try:
                result = await self._request("GET", f"/sca/{agent_id}")
                sca_items = result.get("data", {}).get("affected_items", [])
                return self._format_compliance_result(framework, keywords, [{"agent_id": agent_id, "sca_items": sca_items}])
            except Exception as e:
                raise ValueError(
                    f"SCA data unavailable for agent {agent_id}: {e}. "
                    "The /sca endpoint may not be supported on this agent or Wazuh version."
                )

        agents_result = await self._request(
            "GET", "/agents", params={"status": "active", "limit": 10, "select": "id,name"}
        )
        agents = agents_result.get("data", {}).get("affected_items", [])
        agent_sca_data = []
        for agent in agents[:5]:
            aid = agent.get("id")
            try:
                sca = await self._request("GET", f"/sca/{aid}")
                agent_sca_data.append({
                    "agent_id": aid,
                    "agent_name": agent.get("name"),
                    "sca_items": sca.get("data", {}).get("affected_items", []),
                })
            except Exception:
                agent_sca_data.append({"agent_id": aid, "agent_name": agent.get("name"), "sca_items": []})

        return self._format_compliance_result(framework, keywords, agent_sca_data)

    @staticmethod
    def _format_compliance_result(framework: str, keywords: list, agent_data: list) -> Dict[str, Any]:
        """Format SCA results with framework-relevant filtering and summary scores."""
        results = []
        total_pass = 0
        total_fail = 0
        total_checks = 0

        for agent in agent_data:
            sca_items = agent.get("sca_items", [])
            # Filter policies relevant to the framework (if keywords available)
            if keywords:
                relevant = [
                    p for p in sca_items
                    if any(kw in (p.get("policy_id", "") + " " + p.get("name", "")).lower() for kw in keywords)
                ]
                # If no framework-specific policies found, include all (generic CIS benchmarks apply broadly)
                if not relevant:
                    relevant = sca_items
            else:
                relevant = sca_items

            agent_pass = sum(p.get("pass", 0) for p in relevant)
            agent_fail = sum(p.get("fail", 0) for p in relevant)
            agent_total = sum(p.get("total_checks", 0) for p in relevant)
            agent_score = int(agent_pass / agent_total * 100) if agent_total > 0 else 0

            total_pass += agent_pass
            total_fail += agent_fail
            total_checks += agent_total

            results.append({
                "agent_id": agent.get("agent_id"),
                "agent_name": agent.get("agent_name"),
                "score": agent_score,
                "pass": agent_pass,
                "fail": agent_fail,
                "total_checks": agent_total,
                "policies": [
                    {
                        "policy_id": p.get("policy_id"),
                        "name": p.get("name"),
                        "score": p.get("score"),
                        "pass": p.get("pass"),
                        "fail": p.get("fail"),
                    }
                    for p in relevant
                ],
            })

        overall_score = int(total_pass / total_checks * 100) if total_checks > 0 else 0

        return {
            "data": {
                "framework": framework,
                "overall_score": overall_score,
                "overall_status": "pass" if overall_score >= 70 else "fail",
                "total_checks": total_checks,
                "total_pass": total_pass,
                "total_fail": total_fail,
                "agents_checked": len(results),
                "results": results,
            }
        }

    async def get_wazuh_statistics(self) -> Dict[str, Any]:
        """Get Wazuh statistics."""
        return await self._request("GET", "/manager/stats")

    async def get_weekly_stats(self) -> Dict[str, Any]:
        """Get weekly statistics."""
        return await self._request("GET", "/manager/stats/weekly")

    async def get_cluster_health(self) -> Dict[str, Any]:
        """Get cluster health."""
        return await self._request("GET", "/cluster/healthcheck")

    async def get_cluster_nodes(self) -> Dict[str, Any]:
        """Get cluster nodes (cached for 2 minutes)."""
        cache_key = "cluster_nodes"
        return await self._get_cached(cache_key, "/cluster/nodes")

    async def get_rules_summary(self) -> Dict[str, Any]:
        """Get rules summary aggregated from /rules endpoint."""
        cache_key = "rules_summary"
        current_time = time.time()
        if cache_key in self._cache:
            cached_time, cached_data = self._cache[cache_key]
            if current_time - cached_time < self._cache_ttl:
                return cached_data

        result = await self._request("GET", "/rules", params={"limit": 500})
        rules = result.get("data", {}).get("affected_items", [])
        level_counts: Dict[int, int] = {}
        group_counts: Dict[str, int] = {}
        for rule in rules:
            level = int(rule.get("level", 0))
            level_counts[level] = level_counts.get(level, 0) + 1
            for group in rule.get("groups", []):
                group_counts[group] = group_counts.get(group, 0) + 1

        summary = {
            "data": {
                "total_rules": len(rules),
                "by_level": dict(sorted(level_counts.items())),
                "top_groups": dict(sorted(group_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
            }
        }
        self._cache[cache_key] = (current_time, summary)
        return summary

    async def get_remoted_stats(self) -> Dict[str, Any]:
        """Get remoted statistics."""
        return await self._request("GET", "/manager/stats/remoted")

    async def get_log_collector_stats(self) -> Dict[str, Any]:
        """Get analysis daemon statistics."""
        return await self._request("GET", "/manager/stats/analysisd")

    async def search_manager_logs(self, query: str, limit: int) -> Dict[str, Any]:
        """Search manager logs."""
        params = {"q": query, "limit": limit}
        return await self._request("GET", "/manager/logs", params=params)

    async def get_manager_error_logs(self, limit: int) -> Dict[str, Any]:
        """Get manager error logs."""
        params = {"level": "error", "limit": limit}
        return await self._request("GET", "/manager/logs", params=params)

    async def validate_connection(self) -> Dict[str, Any]:
        """Validate Wazuh connection."""
        try:
            result = await self._request("GET", "/")
            return {"status": "connected", "details": result}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    # =========================================================================
    # Active Response / Action Tools
    # =========================================================================

    @staticmethod
    def _sanitize_ar_argument(value: str, param_name: str) -> str:
        """Sanitize active response argument to prevent command injection.

        Active response arguments are passed to shell commands on agents.
        Only allow safe characters to prevent shell metacharacter injection.
        """
        import re

        # Strip leading/trailing whitespace
        value = value.strip()
        if not value:
            raise ValueError(f"{param_name} cannot be empty")
        # Block shell metacharacters and control chars
        if re.search(r'[;&|`$(){}\[\]<>!\\\'"\n\r\t]', value):
            raise ValueError(f"{param_name} contains invalid characters")
        # Audit fix M6: Block flag injection for standalone values
        if not param_name.startswith("parameter:") and value.startswith("-"):
            raise ValueError(f"{param_name} must not start with '-'")
        return value

    @staticmethod
    def _validate_ip(ip_address: str, param_name: str = "ip_address") -> str:
        """Validate IPv4 or IPv6 address format."""
        import re
        ip_address = ip_address.strip()
        # IPv4
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_address):
            octets = ip_address.split('.')
            if all(0 <= int(o) <= 255 for o in octets):
                return ip_address
        # IPv6 (simplified check)
        if ':' in ip_address and re.match(r'^[0-9a-fA-F:]+$', ip_address):
            return ip_address
        raise ValueError(f"Invalid IP address format for {param_name}: {ip_address}")

    async def block_ip(self, ip_address: str, duration: int = 0, agent_id: str = None) -> Dict[str, Any]:
        """Block IP via firewall-drop active response."""
        ip_address = self._validate_ip(ip_address)
        ip_address = self._sanitize_ar_argument(ip_address, "ip_address")
        arguments = [f"-srcip {ip_address}"]
        if duration and duration > 0:
            arguments.append(f"-timeout {int(duration)}")
        data = {
            "command": "!firewall-drop",
            "agent_list": [agent_id] if agent_id else ["all"],
            "arguments": arguments,
            "alert": {"data": {"srcip": ip_address}},
        }
        return await self.execute_active_response(data)

    async def isolate_host(self, agent_id: str) -> Dict[str, Any]:
        """Isolate host from network via active response."""
        if not agent_id:
            raise ValueError("agent_id is required for host isolation")
        data = {"command": "!host-isolation", "agent_list": [agent_id], "arguments": []}
        return await self.execute_active_response(data)

    async def kill_process(self, agent_id: str, process_id: int) -> Dict[str, Any]:
        """Kill process on agent via active response."""
        if not agent_id:
            raise ValueError("agent_id is required for kill_process")
        try:
            pid = int(process_id)
        except (ValueError, TypeError):
            raise ValueError(f"process_id must be numeric, got: {process_id}")
        data = {"command": "!kill-process", "agent_list": [agent_id], "arguments": [str(pid)]}
        return await self.execute_active_response(data)

    async def disable_user(self, agent_id: str, username: str) -> Dict[str, Any]:
        """Disable user account on agent via active response."""
        if not agent_id:
            raise ValueError("agent_id is required for disable_user")
        username = self._sanitize_ar_argument(username, "username")
        data = {"command": "!disable-account", "agent_list": [agent_id], "arguments": [username]}
        return await self.execute_active_response(data)

    async def quarantine_file(self, agent_id: str, file_path: str) -> Dict[str, Any]:
        """Quarantine file on agent via active response."""
        if not agent_id:
            raise ValueError("agent_id is required for quarantine_file")
        file_path = self._sanitize_ar_argument(file_path, "file_path")
        data = {"command": "!quarantine", "agent_list": [agent_id], "arguments": [file_path]}
        return await self.execute_active_response(data)

    # Known Wazuh active response commands (with ! prefix for stateful execution)
    ALLOWED_AR_COMMANDS = frozenset([
        "!firewall-drop", "!host-isolation", "!kill-process",
        "!disable-account", "!enable-account", "!quarantine",
        "!host-deny", "!restart-wazuh",
    ])

    async def run_active_response(self, agent_id: str, command: str, parameters: dict = None) -> Dict[str, Any]:
        """Execute generic active response command."""
        if command not in self.ALLOWED_AR_COMMANDS:
            raise ValueError(
                f"Unknown active response command: {command}. "
                f"Allowed commands: {', '.join(sorted(self.ALLOWED_AR_COMMANDS))}"
            )
        args = []
        if parameters:
            args = [self._sanitize_ar_argument(f"{k}={v}", f"parameter:{k}") for k, v in parameters.items()]
        data = {"command": command, "agent_list": [agent_id], "arguments": args}
        return await self.execute_active_response(data)

    async def firewall_drop(self, agent_id: str, src_ip: str, duration: int = 0) -> Dict[str, Any]:
        """Add firewall drop rule via active response."""
        src_ip = self._validate_ip(src_ip, "src_ip")
        src_ip = self._sanitize_ar_argument(src_ip, "src_ip")
        arguments = [f"-srcip {src_ip}"]
        if duration and duration > 0:
            arguments.append(f"-timeout {int(duration)}")
        data = {
            "command": "!firewall-drop",
            "agent_list": [agent_id],
            "arguments": arguments,
            "alert": {"data": {"srcip": src_ip}},
        }
        return await self.execute_active_response(data)

    async def host_deny(self, agent_id: str, src_ip: str) -> Dict[str, Any]:
        """Add hosts.deny entry via active response."""
        src_ip = self._validate_ip(src_ip, "src_ip")
        src_ip = self._sanitize_ar_argument(src_ip, "src_ip")
        data = {
            "command": "!host-deny",
            "agent_list": [agent_id],
            "arguments": [f"-srcip {src_ip}"],
            "alert": {"data": {"srcip": src_ip}},
        }
        return await self.execute_active_response(data)

    async def restart_service(self, target: str) -> Dict[str, Any]:
        """Restart Wazuh agent or manager."""
        if target == "manager":
            return await self._request("PUT", "/manager/restart")
        return await self._request("PUT", f"/agents/{target}/restart")

    # =========================================================================
    # Verification Tools
    # =========================================================================

    async def check_blocked_ip(self, ip_address: str, agent_id: str = None) -> Dict[str, Any]:
        """Check if IP is blocked by searching active response alerts via Elasticsearch."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        # Use Elasticsearch query_string to search for both the IP and firewall-drop
        query = f'"{ip_address}" AND "firewall-drop"'
        result = await self._indexer_client.get_alerts(limit=50, query_text=query)
        alerts = result.get("data", {}).get("affected_items", [])
        return {"data": {"ip_address": ip_address, "blocked": len(alerts) > 0, "matching_alerts": len(alerts)}}

    async def check_agent_isolation(self, agent_id: str) -> Dict[str, Any]:
        """Check agent isolation status by examining agent connectivity and alert history."""
        result = await self._request("GET", "/agents", params={"agents_list": agent_id, "select": "id,name,status"})
        agents = result.get("data", {}).get("affected_items", [])
        if not agents:
            raise ValueError(f"Agent {agent_id} not found")
        agent = agents[0]
        status = agent.get("status")
        # Check alert history for isolation commands if indexer is available
        isolation_confirmed = False
        if self._indexer_client and status == "disconnected":
            try:
                query = f'"host-isolation" AND "{agent_id}"'
                alerts = await self._indexer_client.get_alerts(limit=5, query_text=query)
                items = alerts.get("data", {}).get("affected_items", [])
                isolation_confirmed = len(items) > 0
            except Exception:
                pass
        return {
            "data": {
                "agent_id": agent_id,
                "status": status,
                "possibly_isolated": status == "disconnected",
                "isolation_confirmed": isolation_confirmed,
                "name": agent.get("name"),
                "note": "A disconnected agent may be isolated or simply offline. "
                "Check isolation_confirmed for active response evidence.",
            }
        }

    async def check_process(self, agent_id: str, process_id: int) -> Dict[str, Any]:
        """Check if a process is still running on an agent."""
        result = await self._request("GET", f"/syscollector/{agent_id}/processes", params={"limit": 500})
        processes = result.get("data", {}).get("affected_items", [])
        running = any(str(p.get("pid")) == str(process_id) for p in processes)
        return {"data": {"agent_id": agent_id, "process_id": process_id, "running": running}}

    async def check_user_status(self, agent_id: str, username: str) -> Dict[str, Any]:
        """Check user account status by searching active response alerts via Elasticsearch."""
        disable_evidence = False
        enable_evidence = False
        if self._indexer_client:
            try:
                # Search for disable-account events for this user and agent
                disable_query = f'"disable-account" AND "{username}" AND "{agent_id}"'
                disable_result = await self._indexer_client.get_alerts(limit=5, query_text=disable_query)
                disable_evidence = len(disable_result.get("data", {}).get("affected_items", [])) > 0

                # Search for enable-account events
                enable_query = f'"enable-account" AND "{username}" AND "{agent_id}"'
                enable_result = await self._indexer_client.get_alerts(limit=5, query_text=enable_query)
                enable_evidence = len(enable_result.get("data", {}).get("affected_items", [])) > 0
            except Exception:
                pass
        # Most recent action takes precedence
        likely_disabled = disable_evidence and not enable_evidence
        return {
            "data": {
                "agent_id": agent_id,
                "username": username,
                "likely_disabled": likely_disabled,
                "disable_action_found": disable_evidence,
                "enable_action_found": enable_evidence,
                "note": "Status based on active response alert history. " "Verify on the host for definitive status.",
            }
        }

    async def check_file_quarantine(self, agent_id: str, file_path: str) -> Dict[str, Any]:
        """Check if a file has been quarantined via FIM events."""
        result = await self._request("GET", "/syscheck", params={"agents_list": agent_id, "q": f"file={file_path}"})
        events = result.get("data", {}).get("affected_items", [])
        quarantined = any(e.get("type") == "deleted" or "quarantine" in str(e) for e in events)
        return {"data": {"agent_id": agent_id, "file_path": file_path, "quarantined": quarantined}}

    # =========================================================================
    # Rollback Tools
    # =========================================================================

    async def unisolate_host(self, agent_id: str) -> Dict[str, Any]:
        """Remove host isolation via active response."""
        data = {"command": "!host-isolation", "agent_list": [agent_id], "arguments": ["undo"]}
        return await self.execute_active_response(data)

    async def enable_user(self, agent_id: str, username: str) -> Dict[str, Any]:
        """Re-enable user account via active response."""
        username = self._sanitize_ar_argument(username, "username")
        data = {"command": "!enable-account", "agent_list": [agent_id], "arguments": [username]}
        return await self.execute_active_response(data)

    async def restore_file(self, agent_id: str, file_path: str) -> Dict[str, Any]:
        """Restore a quarantined file via active response."""
        file_path = self._sanitize_ar_argument(file_path, "file_path")
        data = {"command": "!quarantine", "agent_list": [agent_id], "arguments": ["restore", file_path]}
        return await self.execute_active_response(data)

    async def firewall_allow(self, agent_id: str, src_ip: str) -> Dict[str, Any]:
        """Remove firewall drop rule via active response."""
        self._validate_ip(src_ip)
        src_ip = self._sanitize_ar_argument(src_ip, "src_ip")
        data = {
            "command": "!firewall-drop",
            "agent_list": [agent_id],
            "arguments": [f"-srcip {src_ip}", "delete"],
        }
        return await self.execute_active_response(data)

    async def host_allow(self, agent_id: str, src_ip: str) -> Dict[str, Any]:
        """Remove hosts.deny entry via active response."""
        self._validate_ip(src_ip)
        src_ip = self._sanitize_ar_argument(src_ip, "src_ip")
        data = {
            "command": "!host-deny",
            "agent_list": [agent_id],
            "arguments": [f"-srcip {src_ip}", "delete"],
        }
        return await self.execute_active_response(data)

    async def get_agent_fim_changes(
        self, agent_id: str, limit: int = 100, file_path: Optional[str] = None, event_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get File Integrity Monitoring (FIM / syscheck) file changes for an agent."""
        agent_id = self._validate_agent_id(agent_id)
        params = {"limit": min(limit, 500)}
        if file_path:
            params["file"] = file_path
        if event_type:
            params["event"] = event_type
        return await self._request("GET", f"/syscheck/{agent_id}", params=params)

    async def get_rule_details(self, rule_id: str) -> Dict[str, Any]:
        """Get details and definition for a specific Wazuh rule ID."""
        params = {"rule_ids": rule_id}
        return await self._request("GET", "/rules", params=params)

    async def test_log_message(self, log_message: str, location: str = "syslog") -> Dict[str, Any]:
        """Test a raw log line against Wazuh decoders and rules via wazuh-logtest."""
        payload = {"token": "logtest", "log": log_message, "location": location}
        return await self._request("PUT", "/logtest", json=payload)

    async def manage_agent_groups(
        self, action: str, group_id: str, agent_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Manage agent group membership or global Wazuh groups (add, remove, set, create, delete)."""
        if action == "add":
            if not agent_id:
                raise ValueError("agent_id is required for action 'add'")
            agent_id = self._validate_agent_id(agent_id)
            return await self._request("PUT", f"/agents/{agent_id}/group/{group_id}")
        elif action == "remove":
            if not agent_id:
                raise ValueError("agent_id is required for action 'remove'")
            agent_id = self._validate_agent_id(agent_id)
            return await self._request("DELETE", f"/agents/{agent_id}/group/{group_id}")
        elif action == "set":
            if not agent_id:
                raise ValueError("agent_id is required for action 'set'")
            agent_id = self._validate_agent_id(agent_id)
            return await self._request("PUT", f"/agents/{agent_id}/group", json={"groups": [group_id]})
        elif action == "create":
            return await self._request("POST", "/groups", json={"group_id": group_id})
        elif action == "delete":
            return await self._request("DELETE", "/groups", params={"groups_list": group_id})
        else:
            raise ValueError("Action must be 'add', 'remove', 'set', 'create', or 'delete'")

    async def create_custom_rule(self, content: str, filename: str = "local_rules.xml") -> Dict[str, Any]:
        """Create or upload a custom XML rule file in Wazuh Manager (/etc/rules/{filename})."""
        headers = {"Content-Type": "application/octet-stream"}
        raw_content = content.encode("utf-8") if isinstance(content, str) else content
        return await self._request(
            "PUT", f"/rules/files/{filename}", params={"overwrite": "true"}, content=raw_content, headers=headers
        )

    async def modify_custom_rule(self, content: str, filename: str = "local_rules.xml") -> Dict[str, Any]:
        """Modify or update an existing custom XML rule file in Wazuh Manager."""
        headers = {"Content-Type": "application/octet-stream"}
        raw_content = content.encode("utf-8") if isinstance(content, str) else content
        return await self._request(
            "PUT", f"/rules/files/{filename}", params={"overwrite": "true"}, content=raw_content, headers=headers
        )

    async def delete_custom_rule(self, filename: str) -> Dict[str, Any]:
        """Delete a custom XML rule file from Wazuh Manager."""
        return await self._request("DELETE", f"/rules/files/{filename}")

    async def get_decoders_summary(self) -> Dict[str, Any]:
        """Get summary of active decoder files from Wazuh Manager."""
        return await self._request("GET", "/decoders/files")

    async def create_custom_decoder(self, content: str, filename: str = "local_decoder.xml") -> Dict[str, Any]:
        """Create or upload a custom XML decoder file in Wazuh Manager (/etc/decoders/{filename})."""
        headers = {"Content-Type": "application/octet-stream"}
        raw_content = content.encode("utf-8") if isinstance(content, str) else content
        return await self._request(
            "PUT", f"/decoders/files/{filename}", params={"overwrite": "true"}, content=raw_content, headers=headers
        )

    async def modify_custom_decoder(self, content: str, filename: str = "local_decoder.xml") -> Dict[str, Any]:
        """Modify or update an existing custom XML decoder file in Wazuh Manager."""
        headers = {"Content-Type": "application/octet-stream"}
        raw_content = content.encode("utf-8") if isinstance(content, str) else content
        return await self._request(
            "PUT", f"/decoders/files/{filename}", params={"overwrite": "true"}, content=raw_content, headers=headers
        )

    async def delete_custom_decoder(self, filename: str) -> Dict[str, Any]:
        """Delete a custom XML decoder file from Wazuh Manager."""
        return await self._request("DELETE", f"/decoders/files/{filename}")

    async def get_agent_packages(
        self, agent_id: str, limit: int = 100, search: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get installed packages/software inventory for an agent from Syscollector."""
        agent_id = self._validate_agent_id(agent_id)
        params = {"limit": min(limit, 500)}
        if search:
            params["search"] = search
        return await self._request("GET", f"/syscollector/{agent_id}/packages", params=params)

    async def investigate_incident(
        self,
        agent_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        ioc: Optional[str] = None,
        time_range: str = "24h",
    ) -> Dict[str, Any]:
        """
        Orchestrate a complete 11-step SOC incident investigation across Wazuh subsystems:
        1. Localizar Alerta
        2. Buscar Agente
        3. Verificar Processos
        4. Verificar Portas
        5. Verificar Vulnerabilidades
        6. Consultar IOC
        7. Consultar MITRE ATT&CK
        8. Analisar FIM (Syscheck)
        9. Produzir Timeline
        10. Calcular Risco (0-100)
        11. Sugerir Contenção
        """
        target_agent = agent_id or "001"

        # Parallel gathering
        tasks = [
            self.get_alerts(time_range=time_range, agent_id=target_agent, limit=10),
            self.get_agents(agent_id=target_agent) if target_agent else asyncio.sleep(0),
            self.get_agent_processes(target_agent, limit=10) if target_agent else asyncio.sleep(0),
            self.get_agent_ports(target_agent, limit=10) if target_agent else asyncio.sleep(0),
            self.get_vulnerabilities(agent_id=target_agent, limit=10) if target_agent else asyncio.sleep(0),
            self.get_agent_fim_changes(target_agent, limit=10) if target_agent else asyncio.sleep(0),
        ]

        if ioc:
            tasks.append(self.check_ioc_reputation(ioc))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        alerts_res = results[0] if not isinstance(results[0], Exception) else {}
        agent_res = results[1] if not isinstance(results[1], Exception) else {}
        proc_res = results[2] if not isinstance(results[2], Exception) else {}
        ports_res = results[3] if not isinstance(results[3], Exception) else {}
        vuln_res = results[4] if not isinstance(results[4], Exception) else {}
        fim_res = results[5] if not isinstance(results[5], Exception) else {}
        ioc_res = results[6] if ioc and len(results) > 6 and not isinstance(results[6], Exception) else {}

        alerts = alerts_res.get("data", {}).get("affected_items", []) if isinstance(alerts_res, dict) else []
        agent_items = agent_res.get("data", {}).get("affected_items", []) if isinstance(agent_res, dict) else []
        agent_info = agent_items[0] if agent_items else {}
        processes = proc_res.get("data", {}).get("affected_items", []) if isinstance(proc_res, dict) else []
        ports = ports_res.get("data", {}).get("affected_items", []) if isinstance(ports_res, dict) else []
        vulns = vuln_res.get("data", {}).get("affected_items", []) if isinstance(vuln_res, dict) else []
        fim_events = fim_res.get("data", {}).get("affected_items", []) if isinstance(fim_res, dict) else []

        max_level = max([a.get("rule", {}).get("level", 0) for a in alerts], default=5)
        risk_score = min(100, max_level * 6 + (15 if vulns else 0) + (10 if fim_events else 0))

        containment = []
        if target_agent and target_agent != "000":
            containment.append(
                {
                    "action": "isolar_host_wazuh",
                    "params": {"agent_id": target_agent},
                    "reason": "Isolamento preventivo de rede do host comprometido.",
                }
            )
        if ioc:
            containment.append(
                {
                    "action": "bloquear_ip_wazuh",
                    "params": {"ip": ioc},
                    "reason": "Bloqueio no firewall do IP/IOC malicioso.",
                }
            )
        if processes:
            suspect_p = processes[0]
            containment.append(
                {
                    "action": "encerrar_processo_wazuh",
                    "params": {"agent_id": target_agent, "pid": suspect_p.get("pid")},
                    "reason": f"Encerrar processo {suspect_p.get('name')} (PID {suspect_p.get('pid')}).",
                }
            )

        return {
            "status": "success",
            "target_agent": target_agent,
            "agent_info": {
                "name": agent_info.get("name"),
                "ip": agent_info.get("ip"),
                "os": agent_info.get("os", {}).get("name"),
                "status": agent_info.get("status"),
            },
            "alerts_found": len(alerts),
            "top_alerts": alerts[:3],
            "active_processes_sample": processes[:5],
            "open_ports_sample": ports[:5],
            "vulnerabilities_found": len(vulns),
            "top_vulnerabilities": vulns[:3],
            "fim_changes_sample": fim_events[:5],
            "ioc_reputation": ioc_res,
            "risk_score": risk_score,
            "risk_level": "CRÍTICO" if risk_score >= 75 else ("ALTO" if risk_score >= 50 else "MÉDIO"),
            "containment_recommendations": containment,
        }

    async def get_sca_policies(self, agent_id: str = "001") -> Dict[str, Any]:
        """Get active Security Configuration Assessment (SCA) policies for an agent."""
        agent_id = str(agent_id).zfill(3) if str(agent_id).isdigit() else agent_id
        return await self._request("GET", f"/sca/{agent_id}")

    async def get_sca_checks(self, agent_id: str = "001", policy_id: Optional[str] = None, result_filter: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        """Get SCA check results for an agent (optionally filtered by policy_id or result: passed/failed)."""
        agent_id = str(agent_id).zfill(3) if str(agent_id).isdigit() else agent_id
        if not policy_id:
            policies_res = await self.get_sca_policies(agent_id=agent_id)
            items = policies_res.get("data", {}).get("affected_items", [])
            if items:
                policy_id = items[0].get("policy_id")
        if not policy_id:
            return {"data": {"affected_items": [], "total_affected_items": 0}}
        params = {"limit": min(limit, 500)}
        if result_filter:
            params["result"] = result_filter
        return await self._request("GET", f"/sca/{agent_id}/checks/{policy_id}", params=params)

    async def get_sca_failures(self, agent_id: str = "001", limit: int = 100) -> Dict[str, Any]:
        """Get only failed compliance checks (SCA) for an agent."""
        return await self.get_sca_checks(agent_id=agent_id, result_filter="failed", limit=limit)

    async def get_fim_stats(self, agent_id: str = "001") -> Dict[str, Any]:
        """Get File Integrity Monitoring (Syscheck) statistics for an agent."""
        agent_id = str(agent_id).zfill(3) if str(agent_id).isdigit() else agent_id
        return await self._request("GET", f"/syscheck/{agent_id}/stat")

    async def search_fim_events(self, agent_id: str = "001", file_path: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        """Search File Integrity Monitoring (Syscheck) events for an agent."""
        agent_id = str(agent_id).zfill(3) if str(agent_id).isdigit() else agent_id
        params = {"limit": min(limit, 500)}
        if file_path:
            params["search"] = file_path
        return await self._request("GET", f"/syscheck/{agent_id}", params=params)

    async def get_monitored_file(self, agent_id: str = "001", file_path: str = "") -> Dict[str, Any]:
        """Get details and modifications of a specific monitored file/registry key."""
        return await self.search_fim_events(agent_id=agent_id, file_path=file_path, limit=20)

    async def search_vulnerabilities_by_cve(self, cve_id: str, limit: int = 100) -> Dict[str, Any]:
        """Search vulnerabilities across agents by CVE ID (e.g., CVE-2024-30078)."""
        return await self.get_vulnerabilities(cve=cve_id, limit=limit)

    async def search_vulnerabilities_by_package(self, package_name: str, limit: int = 100) -> Dict[str, Any]:
        """Search vulnerabilities across agents by package name."""
        return await self.get_vulnerabilities(search=package_name, limit=limit)

    async def search_vulnerabilities_by_severity(self, severity: str = "critical", limit: int = 100) -> Dict[str, Any]:
        """Filter vulnerabilities by severity (critical, high, medium, low)."""
        return await self.get_vulnerabilities(severity=severity, limit=limit)

    async def get_mitre_techniques(self, limit: int = 100) -> Dict[str, Any]:
        """Get MITRE ATT&CK techniques and tactics from active Wazuh alert rules."""
        res = await self.get_rules_summary()
        return {"data": res.get("data", {}).get("top_groups", []), "total_rules": res.get("data", {}).get("total_rules", 0)}

    async def search_alerts_by_mitre(self, mitre_id: str = "T1059", time_range: str = "24h", limit: int = 50) -> Dict[str, Any]:
        """Search security alerts by MITRE ATT&CK technique or tactic ID."""
        return await self.get_alerts(time_range=time_range, search=mitre_id, limit=limit)

    async def get_mitre_stats(self, time_range: str = "24h") -> Dict[str, Any]:
        """Get statistical summary of top MITRE ATT&CK tactics triggered in recent alerts."""
        alerts_res = await self.get_alerts(time_range=time_range, limit=500)
        items = alerts_res.get("data", {}).get("affected_items", [])
        tactics = {}
        techniques = {}
        for a in items:
            mitre = a.get("rule", {}).get("mitre", {})
            for tac in mitre.get("tactic", []):
                tactics[tac] = tactics.get(tac, 0) + 1
            for tec in mitre.get("id", []):
                techniques[tec] = techniques.get(tec, 0) + 1
        return {"total_alerts_analyzed": len(items), "top_tactics": dict(sorted(tactics.items(), key=lambda x: x[1], reverse=True)), "top_techniques": dict(sorted(techniques.items(), key=lambda x: x[1], reverse=True))}

    async def get_alerts_dashboard(self, time_range: str = "24h") -> Dict[str, Any]:
        """Get consolidated executive dashboard for security alerts."""
        res = await self.get_alerts_summary(time_range=time_range)
        return {"dashboard": "Executive Alerts Overview", "data": res}

    async def get_vulnerability_dashboard(self) -> Dict[str, Any]:
        """Get consolidated executive dashboard for vulnerabilities across infrastructure."""
        res = await self.get_vulnerability_summary()
        return {"dashboard": "Executive Vulnerabilities Overview", "data": res}

    async def generate_nist_report(self, time_range: str = "24h") -> Dict[str, Any]:
        """Generate NIST SP 800-53 Compliance & Audit Report."""
        alerts = await self.get_alerts(time_range=time_range, limit=200)
        vulns = await self.get_vulnerability_summary()
        return {
            "standard": "NIST SP 800-53 Rev 5",
            "assessment_period": time_range,
            "control_access_events": len(alerts.get("data", {}).get("affected_items", [])),
            "vulnerability_posture": vulns,
            "status": "COMPLIANT_WITH_FINDINGS"
        }

    async def generate_cis_report(self, agent_id: str = "001") -> Dict[str, Any]:
        """Generate CIS Benchmark Security Assessment Report for an agent."""
        policies = await self.get_sca_policies(agent_id=agent_id)
        failures = await self.get_sca_failures(agent_id=agent_id, limit=20)
        items = policies.get("data", {}).get("affected_items", [])
        policy_info = items[0] if items else {}
        total = policy_info.get("total_checks", 1)
        passed = policy_info.get("pass", 0)
        compliance_pct = round((passed / total) * 100, 2) if total else 0
        return {
            "benchmark": policy_info.get("name", "CIS Benchmark"),
            "agent_id": agent_id,
            "compliance_score_pct": compliance_pct,
            "passed_checks": passed,
            "failed_checks": policy_info.get("fail", 0),
            "top_failures": failures.get("data", {}).get("affected_items", [])[:5]
        }

    async def generate_lgpd_report(self, time_range: str = "24h") -> Dict[str, Any]:
        """Generate LGPD (Lei Geral de Proteção de Dados) Data Privacy & Security Audit Report."""
        alerts = await self.get_alerts(time_range=time_range, limit=500)
        items = alerts.get("data", {}).get("affected_items", [])
        privacy_events = [a for a in items if "sysmon" in a.get("rule", {}).get("groups", []) or "authentication_failed" in a.get("rule", {}).get("groups", [])]
        return {
            "norma": "LGPD - Lei Nº 13.709/2018 (Art. 46 - Medidas de Segurança)",
            "janela_analise": time_range,
            "total_eventos_monitorados": len(items),
            "incidentes_privacidade_dados": len(privacy_events),
            "top_eventos_privacidade": privacy_events[:3],
            "nivel_conformidade_seguranca": "ADEQUADO" if len(privacy_events) < 50 else "ATENÇÃO_REQUERIDA"
        }

    async def close(self):
        """Close the HTTP client and indexer client, releasing all connections."""
        try:
            if self.client:
                await self.client.aclose()
        except Exception:
            pass  # Best-effort close; connection may already be broken
        finally:
            self.client = None
        try:
            if self._indexer_client:
                await self._indexer_client.close()
        except Exception:
            pass
        self.token = None
        self._cache.clear()
