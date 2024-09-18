interface Listing {
  id: string;
  createdAt: Date;
  updatedAt: Date;
  rent: number;
  brokerFee: number;
  squareFootage: number;
  bedrooms: number;
  bathrooms: number;
  availableDate: Date;
  streetAddress: string;
  zillowUrl: string;
}