import React from 'react';
import { Listing } from 'frontend/src/schema/listing';

// SEC-05: only an http or https link may reach an href; a javascript:
// value bound there executes in the document (CWE-79)
const NAVIGABLE_LINK = /^https?:\/\//i;

// value states the rent styling distinguishes. The repository ships no
// stylesheet, so the class names carry the state for a future one while
// these inline values make the distinction visible today.
const RENT_STYLE: { [state: string]: React.CSSProperties } = {
  negative: { color: 'rgb(176, 0, 32)', fontWeight: 700 },
  zero: { color: 'rgb(102, 102, 102)', fontWeight: 400 },
  positive: { color: 'rgb(17, 17, 17)', fontWeight: 600 },
  unknown: { color: 'rgb(102, 102, 102)', fontStyle: 'italic' },
};

// the glyph shown where the API supplies no value, so no card can
// render the literal text "undefined" or "null"
const MISSING_VALUE = '\u2014';

function rentState(rent: unknown): string {
  if (typeof rent !== 'number' || !Number.isFinite(rent)) {
    return 'unknown';
  }
  if (rent < 0) {
    return 'negative';
  }
  return rent === 0 ? 'zero' : 'positive';
}

function formatRent(rent: unknown): string {
  if (typeof rent !== 'number' || !Number.isFinite(rent)) {
    return MISSING_VALUE;
  }
  return `${rent.toLocaleString('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}/month`;
}

function formatMeasure(value: unknown): string {
  return typeof value === 'number' && Number.isFinite(value)
    ? value.toLocaleString('en-US')
    : MISSING_VALUE;
}

const ListingCard: React.FC<{ listing: Listing }> = ({ listing }) => {
  // the API publishes these names; reading any other name renders an
  // empty heading and the literal string "undefined" to every reader,
  // assistive technology included
  const {
    street_address,
    rent,
    bedrooms,
    bathrooms,
    square_footage,
    zillow_url
  } = listing;

  const address =
    typeof street_address === 'string' && street_address.trim() !== ''
      ? street_address
      : 'Address unavailable';
  const state = rentState(rent);
  const link = typeof zillow_url === 'string' ? zillow_url : '';

  return (
    <div className="listing-card">
      <div className="listing-details">
        <h2 style={{ overflowWrap: 'anywhere' }}>{address}</h2>
        <p className={`rent rent-${state}`} style={RENT_STYLE[state]}>
          {formatRent(rent)}
        </p>
        <div className="property-info" style={{ display: 'flex', gap: 8 }}>
          <span>{formatMeasure(bedrooms)} bed</span>
          <span>{formatMeasure(bathrooms)} bath</span>
          <span>{formatMeasure(square_footage)} sqft</span>
        </div>
        {NAVIGABLE_LINK.test(link) ? (
          <a
            href={link}
            target="_blank"
            rel="noopener noreferrer"
            className="zillow-link"
          >
            View on Zillow
          </a>
        ) : (
          <span className="zillow-link">Zillow link unavailable</span>
        )}
      </div>
    </div>
  );
};

export default ListingCard;