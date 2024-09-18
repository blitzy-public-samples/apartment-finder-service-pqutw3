interface ZipCode {
  code: string;
}

interface Criteria {
  field: string;
  operator: string;
  value: string;
}

interface Filter {
  id: string;
  userId: string;
  name: string;
  createdAt: Date;
  lastUsed: Date;
  zipCodes: ZipCode[];
  criteria: Criteria[];
}

// HUMAN ASSISTANCE NEEDED
// Please review the Filter interface to ensure all properties are correctly defined and no additional properties are needed for production use.