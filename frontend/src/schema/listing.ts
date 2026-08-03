// The body GET /listings/ serves, exactly as backend/app/schema/listing.py
// declares it: an integer primary key, snake_case names, ISO-8601 date-time
// strings, and null for every nullable column.
export interface Listing {
  id: number;
  created_at: string;
  updated_at: string;
  rent: number;
  broker_fee: number | null;
  square_footage: number | null;
  bedrooms: number | null;
  bathrooms: number | null;
  available_date: string | null;
  street_address: string | null;
  zillow_url: string | null;
}

// The two bounds GET /listings/ declares. No other query parameter is read.
export interface ListingQuery {
  skip?: number;
  limit?: number;
}
