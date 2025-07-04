===================================================================
aiocfscrape with Async httpx Client Initalization for mordern control 
===================================================================

An asynchronous Python module designed to bypass Cloudflare's anti-bot protection.
Built on top of aiohttp ClientSession, this solution inherits from the proven `cfscrape <https://github.com/Anorov/cloudflare-scrape>`_ module.

This library enables concurrent crawling of web resources protected by Cloudflare using Python 3's 
`asyncio <https://docs.python.org/3/library/asyncio-dev.html>`_ framework.

The latest implementation features an httpx AsyncClient architecture that provides persistent client 
management, eliminating the need for context managers while ensuring efficient resource handling.


Getting Started
===============

.. code:: python

  import asyncio
  from aiocfscrape import CloudflareScraper
  
  # Initialize the scraper with custom configuration
  scraper = CloudflareScraper(
      headers={"User-Agent": user_agent},
      proxy=proxy_url,
      verify=ssl_context,
      timeout=30
  )
  
  # Perform multiple requests as needed
  response = await scraper.get("https://example.com")
  
  # Remember to close the session when done
  await scraper.aclose() 

  NOTE: Currently  it dosen't support http2 


Requirements
============

- Python ``3.5.3+``
- `aiohttp <https://pypi.python.org/pypi/aiohttp>`_ ``>=3.1.3, < 3.13``
- `js2py <https://pypi.python.org/pypi/Js2Py>`_


License
=======

This project is licensed under the MIT License.


