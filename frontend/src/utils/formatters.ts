import dayjs from 'dayjs';

export function formatCurrency(amount: number): string {
  const formatter = new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
  });
  return formatter.format(amount);
}

export function formatDate(dateString: string): string {
  // HUMAN ASSISTANCE NEEDED
  // Please verify the desired date format for the application
  // Current implementation uses 'MMMM D, YYYY' format
  return dayjs(dateString).format('MMMM D, YYYY');
}