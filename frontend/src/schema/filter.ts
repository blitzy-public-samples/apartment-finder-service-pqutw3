export interface ZipCode {
  code: string;
}

export interface Criteria {
  field: string;
  operator: string;
  value: string;
}

// The body GET /filters/ and POST /filters/ serve, exactly as
// backend/app/schema/filter.py declares it: integer key and foreign key,
// snake_case names, and ISO-8601 date-time strings.
export interface Filter {
  id: number;
  user_id: number;
  name: string;
  created_at: string;
  last_used: string | null;
  zip_codes: ZipCode[];
  criteria: Criteria[];
}

// SEC-05: the writable-field allow-list POST /filters/ accepts. Any other
// key is refused with 422, and the server owns id, user_id, created_at,
// last_used and zip_codes.
export interface FilterCreate {
  name: string;
  criteria: Criteria[];
}

// The value the filter form holds while a user edits it. It is a UI model,
// not a wire body: criteria arrive keyed by input name in camelCase, and the
// zip-code field is a plain list of strings. frontend/src/services/api.ts
// maps it to FilterCreate; nothing sends this shape to the server.
export interface FilterFormValue {
  name?: string;
  zipCodes?: string[];
  criteria: Record<string, string | number> | Criteria[];
}
